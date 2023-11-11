# -*- coding: utf-8 -*-
'''
Execution module for working with Linux build data (patch group owner, patch
group class, etc.).
Intended to be called from the REST API by external build systems.

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import
import json
import logging
import re


PARAMS = {}


def __virtual__():
    ret = True
    log = logging.getLogger(__name__)
    ddict = __salt__['pillar.get']('provision:linux:teams')
    logging.debug('Teams pillar data: %s', ddict)
    PARAMS['patch_group_owners'] = {}
    for pgo, pdict in ddict.items():
        PARAMS['patch_group_owners'][pgo] = pdict['full_name']
    log.debug('patch_group_owners: %s', PARAMS['patch_group_owners'])
    ddict = __salt__['pillar.get']('provision:linux:functions')
    logging.debug('Functions pillar data: %s', ddict)
    PARAMS['functions'] = list(ddict.keys())
    log.debug('functions: %s', PARAMS['functions'])
    PARAMS.update(__salt__['pillar.get']('postinst:static_persona'))
    if not PARAMS['patch_group_owners']:
        log.error('patch_group_owners data is empty')
        ret = False
    if not PARAMS['functions']:
        log.error('functions data is empty')
        ret = False
    return ret


class DataFile():
    '''
    Base class for central data containers.
    It is backed with a file that can be read/written at any time.
    '''
    def __init__(self):
        self._datafile = ''
        self._data = {}

    def set_datafile(self, datafile):
        '''
        :param str datafile: Full path to datafile
        :raises: ValueError if invalid path
        '''
        if not datafile.startswith('/'):
            ret = {'msg': 'Invalid path, must be absolute',
                   'items': [datafile]}
            raise ValueError(ret)
        self._datafile = datafile

    def get_datafile(self):
        '''
        :rtype: str
        :returns: Full path to datafile
        '''
        return self._datafile

    def write_file(self):
        '''
        Write current data to backend file.

        :raises: IOError
        '''
        try:
            with open(self._datafile, 'w', encoding='utf-8') as file_desc:
                json.dump(self._data, file_desc)
        except IOError as err:
            ret = {'msg': 'Could not write to data file',
                   'items': [str(err)]}
            raise IOError(ret) from err

    def read_file(self, must_exist=True):
        '''
        Read backend file data.

        :raises: IOError
        '''
        json_data = ''
        try:
            with open(self._datafile, encoding='utf-8') as file_desc:
                json_data = json.load(file_desc)
        except IOError as err:
            ret = {'msg': 'Could not read from data file', 'items': [str(err)]}
            if must_exist:
                raise IOError(ret) from err
            log = logging.getLogger(__name__)
            log.warning('%s', ret)
        if json_data:
            self._data.update(json_data)


class Handler(DataFile):
    '''
    Central data container for Persona data.  Stored in pillar under
    "postinst:persona".

    Structure for each build (valid values defined in pillar -
    postinst:static_persona):
        build_name:
          role: value
          patch_group_owner: value
          patch_group_class: value
          functions (optional):
            - <func1>
            - <func2>
    '''
    def __init__(self, params):
        super().__init__()
        self._patch_group_owners = params['patch_group_owners']
        self._patch_group_classes = params['patch_group_classes']
        self._functions = params['functions']
        self._roles = params['roles']
        self._required_keys = params['required_keys']
        self._optional_keys = params['optional_keys']
        # Base data
        self._data = {'postinst': {'persona': {}}}
        # Data file
        self.set_datafile(params['data_file'])

    def _valid_pgo(self, pgo):
        return pgo in list(self._patch_group_owners.values())

    def _valid_pgc(self, pgc):
        return pgc in self._patch_group_classes

    def _valid_role(self, role):
        return role in self._roles

    def _invalid_functions(self, functions):
        invalid = []
        for function in functions:
            if function not in self._functions:
                invalid.append(function)
        return invalid

    @staticmethod
    def valid_build_name(name):
        '''
        Check build name validity.

        :param str name: Name to check
        :rtype: bool
        '''
        return re.match(r'[a-zA-Z0-9\-]+$', name) is not None

    def _validate(self, data, build_name):
        '''
        Validate data for a given build name.

        :param dict data: Persona data to validate.  Missing keys will be
        looked up in the currently loaded dataset for the given build name.
        :raises: ValueError on invalid values
        '''
        # Validate keys - only report a key as missing if not already in
        # existing data
        input_keys = set(data.keys())
        required_keys = set(self._required_keys)
        missing_input_keys = required_keys.difference(input_keys)
        existing_data = self._data['postinst']['persona'].get(build_name, {})
        if existing_data:
            existing_keys = set(existing_data.keys())
            missing_keys = missing_input_keys.difference(existing_keys)
        else:
            missing_keys = missing_input_keys
        if missing_keys:
            ret = {'msg': 'Missing required persona key(s)',
                   'items': list(missing_keys)}
            raise ValueError(ret)
        valid_keys = set(self._required_keys+self._optional_keys)
        invalid_keys = input_keys.difference(valid_keys)
        if invalid_keys:
            ret = {'msg': 'Invalid persona key(s)',
                   'items': list(invalid_keys)}
            raise ValueError(ret)
        # Patch group owner - do a reverse lookup on the full team name
        # (input_pgo) to find the short name
        pgo = ''
        input_pgo = data.get('patch_group_owner')
        if not self._valid_pgo(input_pgo):
            ret = {'msg': 'Invalid patch group owner',
                   'items': [input_pgo],
                   'valid': list(self._patch_group_owners.values())}
            raise ValueError(ret)
        for short, full in self._patch_group_owners.items():
            if input_pgo == full:
                pgo = short
        if not pgo:
            pgo = existing_data.get('patch_group_owner')
        data['patch_group_owner'] = pgo
        # Patch group class
        pgc = data.get('patch_group_class') or \
            existing_data.get('patch_group_class')
        if not self._valid_pgc(pgc):
            ret = {'msg': 'Invalid patch group class',
                   'items': [pgc],
                   'valid': self._patch_group_classes}
            raise ValueError(ret)
        # Role
        role = data.get('role') or existing_data.get('role')
        if not self._valid_role(role):
            ret = {'msg': 'Invalid role',
                   'items': [role],
                   'valid': self._roles}
            raise ValueError(ret)
        # Functions
        functions = data.get('functions') or existing_data.get('functions')
        if functions:
            invalid = self._invalid_functions(functions)
            if invalid:
                ret = {'msg': 'Invalid function(s)',
                       'items': invalid,
                       'valid': self._functions}
                raise ValueError(ret)

    def set_build_data(self, build_name, build_data=None):
        '''
        Set data for a specific build.

        :param str build_name: Name of build for which to set data
        :param dict build_data: May contain the following keys
        (invalid/missing keys are ignored):
            role
            functions
            patch_group_owner
            patch_group_class
        If None, a skeleton dataset is created for build_name.  It has this
        structure:
            role: ''
            patch_group_owner: ''
            patch_group_class: ''
        :raises: ValueError on invalid values
        '''
        builds = self._data['postinst']['persona']
        if build_data is not None:
            self._validate(build_data, build_name)
            input_pgo = build_data['patch_group_owner']
            build_data['patch_group_owner'] = input_pgo.lower()
            if 'functions' in build_data:
                input_funcs = list(build_data['functions'])
                build_data['functions'] = []
                for input_func in input_funcs:
                    if not input_func:
                        continue
                    build_data['functions'].append(input_func.lower())
            if build_name in builds:
                builds[build_name].update(build_data)
            else:
                builds[build_name] = build_data
        else:
            builds[build_name] = {'role': '',
                                  'patch_group_owner': '',
                                  'patch_group_class': ''}


def persona_options(key):
    '''
    Return available persona options for a specified key.
    Used by external build systems for populating end-user form values.

    :param str key: Lookup key; must be one of:
        * patch_group_owners
        * patch_group_classes
        * roles
        * functions
    :rtype: list
    :returns: Available values for the given key, or a two-item list with
    "INVALID KEY" and the given key
    '''
    log = logging.getLogger(__name__)
    ret = ['INVALID KEY', key]
    if key == 'patch_group_owners':
        ret = list(PARAMS['patch_group_owners'].values())
    elif key == 'patch_group_classes':
        ret = PARAMS['patch_group_classes']
    elif key == 'roles':
        ret = PARAMS['roles']
    elif key == 'functions':
        ret = list(PARAMS['functions'])
    log.debug('ret: %s', ret)
    return ret


def persona_input(input_data, data_file=''):
    '''
    Receive persona data for a build, validate it, and insert it into pillar.

    :param dict input_data: Keys:
        * build_name (str)
        * patch_group_owner (str - must be one of the full_name items from
            provision:linux:teams in pillar)
        * patch_group_class (str)
        * role (str)
        * functions (list)
    :param str data_file: Path to alternate data file (useful for testing).
        If omitted, the file at pillar key `postinst:static_persona:data_file`
        will be used.
    :rtype: dict
    :returns: Keys:
        * msg: Either "Success" or an error message
        * items: List of strings related to an error message, not included on
                 success
        * valid: List of valid values, if any, not included on success
    '''
    ret = {'msg': 'Success'}
    build_name = input_data['build_name']
    del input_data['build_name']
    if not Handler.valid_build_name(build_name):
        ret['msg'] = 'Invalid build name'
        ret['items'] = [build_name]
    else:
        if data_file:
            PARAMS['data_file'] = data_file
        try:
            handler = Handler(PARAMS)
            handler.read_file(must_exist=False)
            handler.set_build_data(build_name, input_data)
            handler.write_file()
        except (IOError, ValueError) as err:
            ret = err.args[0]
    return ret
