# -*- coding: utf-8 -*-
'''
Runner for updating and managing systems data in CMDB

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

import copy
import json
import logging
import requests

PILLAR_DATA = {}


def __virtual__():
    '''
    Get pillar data on module load.
    Master-only and minion-accessible data are merged into PILLAR_DATA.
    '''
    log = logging.getLogger(__name__)
    master_id = __salt__['salt.cmd']('grains.get', 'id')
    all_data = __salt__['pillar.show_pillar'](minion=master_id)
    _ = all_data.get('master', {})
    master_data = _.get('cmdb', '')
    if not master_data:
        log.error('CMDB pillar master data not found, unable to load '
                  'runner module')
        return False
    log.debug('master_data: %s', master_data)
    minion_data = all_data.get('cmdb', {})
    if not minion_data:
        log.error('CMDB pillar minion data not found, unable to load '
                  'runner module')
        return False
    log.debug('minion_data: %s', minion_data)
    PILLAR_DATA.update(master_data)
    PILLAR_DATA.update(minion_data)
    log.debug('PILLAR_DATA: %s', PILLAR_DATA)
    return True


class CmdbApi():
    '''
    Class that communicates via a REST API to a CMDBuild 3.x server.
    '''
    def __new__(cls):
        if not hasattr(cls, '_inst'):
            cls._inst = super(CmdbApi, cls).__new__(cls)
            cls.logger = logging.getLogger(__name__)
            cls.requests_verify = True
            cls.headers = {'CMDBuild-Localization': 'en',
                           'CMDBuild-Localized': 'true',
                           'Content-type': 'application/json',
                           'Accept': 'application/json'}
            cls.main_url = ''
            cls.cards_url_str = ''
        return cls._inst

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def login(self, server, username, password):
        '''
        Authenticate to the CMDB REST API.
        '''
        # Setup URLs
        self.main_url = PILLAR_DATA['main_url'].format(server)
        self.cards_url_str = self.main_url+PILLAR_DATA['cards_url_str']
        auth_url = self.main_url+PILLAR_DATA['auth_url_str']
        # Authenticate
        self.logger.debug("*** Login and get authentication token ")
        data = json.dumps({'username': username,
                           'password': password})
        r = self._request('POST', auth_url, data=data)
        sessionid = r.json()["data"]["_id"]
        self.headers['CMDBuild-Authorization'] = sessionid

    def _request(self, method, url, **kwargs):
        '''
        Wrapper around :meth:requests.request that configures appropriate
        headers, methods, and error checking.
        '''
        _method = method.upper()
        # SSL verification
        kwargs['verify'] = self.requests_verify
        # Setup headers
        t_headers = copy.deepcopy(self.headers)
        if 'headers' in kwargs:
            t_headers.update(kwargs['headers'])
        # HTTP request
        resp = requests.request(_method, url, headers=t_headers, **kwargs)
        self.logger.debug('REQUEST URL: %s', resp.request.url)
        self.logger.debug('RESPONSE JSON: %s', resp.json())
        self.logger.debug('CmdbApi._request content: %s', resp.content)
        content = json.loads(resp.content)
        if not content['success']:
            # Pull actual error messages out of server response
            plain_msgs = []
            for msg_dict in content['messages']:
                plain_msgs.append(msg_dict['message'])
            raise requests.exceptions.HTTPError('\n'.join(plain_msgs))
        return resp

    def lookup_type_id(self, lookup_type, value):
        '''
        Return numeric ID for a value in a CMDB Lookup Type.

        :param str lookup_type: Name of Lookup type in CMDB
        :param str value: String value for which to get ID
        :returns: Numeric ID of value
        :rtype: int
        :raises: CmdbApi.Error if value is not found in the given type
        '''
        ret = None
        url = '{}/lookup_types/{}/values'.format(self.main_url, lookup_type)
        resp = self._request('GET', url)
        resp_json = resp.json()
        for _dict in resp_json['data']:
            if _dict['code'] == value:
                ret = _dict['_id']
                break
        if ret is None:
            err_msg = 'Value ({}) not found in Lookup Type ({})'
            raise CmdbApi.Error(err_msg.format(value, lookup_type))
        return ret

    def card_search(self, class_id, search_filter=None):
        '''
        Search for a card.

        :param str class_id: CMDB class in which to search
        :param dict search_filter: Optional filter to be used in "filter" GET
        param.  Default is None, which returns all cards.
        '''
        cards_url = self.cards_url_str.format(class_id)
        if search_filter is None:
            r = self._request('GET', cards_url)
        else:
            json_filter = json.dumps(search_filter)
            r = self._request('GET', cards_url, params={'filter': json_filter})
        return r.json()

    def update(self, class_id, card_id, data):
        '''
        Update a card with the given data.
        '''
        cards_url = self.cards_url_str.format(class_id)
        url = '{}/{}'.format(cards_url, card_id)
        r = self._request('PUT', url, data=json.dumps(data))
        return r.json()

    def create(self, class_id, data):
        '''
        Create a card with the given data.

        :param str class_id: CMDB class ID in which to create card
        :param dict data: Data to send
        '''
        cards_url = self.cards_url_str.format(class_id)
        r = self._request('POST', cards_url, data=json.dumps(data))
        return r.json()

    def delete(self, class_id, card_id):
        '''
        Delete a card.
        '''
        cards_url = self.cards_url_str.format(class_id)
        url = '{}/{}'.format(cards_url, card_id)
        r = self._request('DELETE', url)
        return r.json()

    class Error(Exception):
        '''
        Exception for errors specific to the containing class.
        '''


class CmdbClass():
    '''
    Manage cards within a CMDB class.
    It is aware of the oddness in the NISystems class where an extra card
    is created for a T-Series physical chassis, in addition to the two cards
    created for the service domain LDOMs.

    For example, the T-Series system "marge" would have 3 cards:
    * marge-pri (control/service domain)
    * marge-sec (service domain)
    * marge (physical chassis)

    For all other CMDB classes, incoming records are treated normally (a single
    system for each record).
    '''
    def __init__(self, class_id):
        self.logger = logging.getLogger(__name__)
        self.class_id = class_id
        # Existing CMDB data
        self.cur_data = {}
        # Incoming sysinfo data
        self.new_data = {}
        # Setup filter for NISystems class
        if self.class_id == PILLAR_DATA['nisystems_class']:
            retired_lookup = PILLAR_DATA['retired_lookup']
            try:
                yes_retired_id = CmdbApi().lookup_type_id(retired_lookup, 'Yes')
            except CmdbApi.Error as err:
                raise CmdbClass.Error(str(err))
            search_filter = {
                'attribute':
                    {'and': [
                        {'simple':
                         {'attribute': 'Owner_Technical',
                          'operator': 'contain',
                          'value': 'unix'}},
                        {'simple':
                         {'attribute': 'Retired',
                          'operator': 'notequal',
                          'value': yes_retired_id}}]}}
            resp_json = CmdbApi().card_search(self.class_id,
                                              search_filter=search_filter)
        else:
            resp_json = CmdbApi().card_search(self.class_id)
        if 'data' not in resp_json:
            msg = 'Error getting card data for class ({}); server response: {}'
            raise CmdbClass.Error(msg.format(self.class_id, resp_json))
        # Report duplicates
        hostnames = [card['System_Name'] for card in resp_json['data']]
        seen = set()
        seen_add = seen.add
        dups = set(x for x in hostnames if x in seen or seen_add(x))
        if dups:
            log_msg = 'Duplicate cards found in class (%s): %s'
            self.logger.warning(log_msg, self.class_id, dups)
        # Build list without duplicates
        for card in resp_json['data']:
            if card['System_Name'] in dups:
                continue
            self.cur_data[card['System_Name']] = card

    def get_all_cards(self):
        '''
        Retrieve all card data in this class.

        :returns: Card data in a list of dicts, one per card
        :rtype: list
        '''
        return list(self.cur_data.values())

    def add_card(self, input_data):
        '''
        Add data for a system.
        '''
        if self.class_id == PILLAR_DATA['nisystems_class']:
            # Separate chassis data from normal data
            chassis_prefix = PILLAR_DATA['chassis_prefix']
            card_data = dict({k: v for k, v in input_data.items()
                              if not k.startswith(chassis_prefix)})
            chassis_card_data = dict({k: v for k, v in input_data.items()
                                      if k.startswith(chassis_prefix)})
            self.logger.debug('NORMAL CARD DATA (%s): %s', self.class_id,
                              card_data)
            self.logger.debug('CHASSIS CARD DATA (%s): %s', self.class_id,
                              chassis_card_data)
            # Add a normal NISystems card
            self.new_data[card_data['System_Name']] = card_data
            # Handle chassis data
            if chassis_card_data:
                # Build new dict for chassis data -
                # this is to combine chassis-specific data (such as CPU and RAM)
                # with data common to both service domains and chassis
                new_dict = {}
                # Strip chassis prefix from keys
                for key, val in chassis_card_data.items():
                    normal_key = key.replace(PILLAR_DATA['chassis_prefix'], '')
                    new_dict[normal_key] = val
                # Add chassis_common data
                chassis_common = PILLAR_DATA['chassis_common']
                for attrib in chassis_common:
                    new_dict[attrib] = card_data[attrib]
                # Add a chassis NISystems card
                self.new_data[new_dict['System_Name']] = new_dict
        else:
            # Add a normal non-NISystems card
            self.new_data[input_data['System_Name']] = input_data

    def update_cards(self):
        '''
        Update all cards in this class, using input data from add_card().
        This will also create new cards.
        '''
        new_names = list(self.new_data.keys())
        cur_names = list(self.cur_data.keys())
        create_names = set(new_names) - set(cur_names)
        update_names = set(new_names) & set(cur_names)
        for hostname, data in self.new_data.items():
            if hostname in create_names:
                try:
                    # Create new card
                    resp_json = CmdbApi().create(self.class_id, data)
                    msg = 'CmdbClass.update_cards resp_json: %s'
                    self.logger.debug(msg, resp_json)
                except requests.exceptions.HTTPError as err:
                    msg = 'HTTPError when creating card for host %s: %s'
                    self.logger.warning(msg, hostname, err)
                    continue
            elif hostname in update_names:
                # Check new data against current
                cur_data = self.cur_data[hostname]
                for key, val in data.items():
                    if cur_data.get(key, '') != val:
                        needs_update = True
                        break
                # Update card
                if needs_update:
                    try:
                        resp_json = CmdbApi().update(self.class_id,
                                                     cur_data['_id'], data)
                        msg = 'CmdbClass.update resp_json: %s'
                        self.logger.debug(msg, resp_json)
                    except requests.exceptions.HTTPError as err:
                        msg = 'HTTPError when updating card for host %s: %s'
                        self.logger.warning(msg, hostname, err)
                        continue

    def delete_card(self, card_id):
        '''
        Delete a card from this class.

        :param int card_id: ID of card to delete
        '''
        resp_json = CmdbApi().delete(self.class_id, card_id)
        self.logger.debug('delete_card: response JSON: %s', resp_json)

    class Error(Exception):
        '''
        Exception for errors specific to the containing class.
        '''


def _setup_api(server_tier):
    logger = logging.getLogger(__name__)
    if server_tier not in ['dev', 'test', 'prod']:
        log_msg = 'Invalid server_tier: ({})'.format(server_tier)
        logger.error(log_msg)
        return False
    # Get API connection data
    server = PILLAR_DATA['{}_server'.format(server_tier)]
    cmdb_grains = __salt__['salt.cmd']('grains.get', 'ni_unix:cmdb')
    if not cmdb_grains:
        log_msg = 'CMDB data not found in master local grains'
        logger.error(log_msg)
        return False
    # Create API singleton and login to server
    try:
        CmdbApi().login(server, cmdb_grains['username'], cmdb_grains['password'])
    except requests.exceptions.HTTPError as err:
        log_msg = 'Connection to CMDB server (%s) failed: %s'
        logger.error(log_msg, server, err)
        return False
    except KeyError as err:
        log_msg = 'Grain not found in master CMDB grains: %s'
        logger.error(log_msg, err)
        return False
    except ValueError as err:
        logger.error('%s', err)
        return False
    return True


def push_data(data, server_tier='prod'):
    '''
    Sends system data to CMDB via REST API.

    :param dict data: Data as returned by the sysinfo execution module

    Example of a single record:
    {
      'saline1': {
        'NISystems': {
          'System_Name': 'saline1',
          'OS_Version': 'Oracle Linux Server 7.7',
          'Production_Dev_Test': 'Production',
          'Functions_Supported': [
            'A function'
          ]
          'Vendor': 'Dell Inc.',
          'RAM': 31574,
          'Owner_Support': '',
          'Owner_User': 'unix',
          'Owner_Technical': '',
          'Owner_Business': 'Global Unix Admins',
          'Serial_Number': 'JCKYZV2',
          'Model': 'PowerEdge R640',
          'CPU': '112 x Intel(R) Xeon(R) Platinum 8180 CPU @ 2.50GHz'
        },
        'UnixPatchAudit': {
          'System_Name': 'saline1',
          'OS_Version': 'Oracle Linux Server 7.7',
          'Production_Dev_Test': 'Production',
          'Functions_Supported': [
            'A function'
          ]
          'Patch_Set': '2020Q3',
          'Kernel_Version': '4.14.35-1902.6.6.el7uek.x86_64',
          'Patch_Time': '2020-07-08T15:19:25Z',
          'Patch_User_Owner': 'unix',
          'Patch_Group_Class': 'pre-release',
          'Patch_Group_Owner': 'unix'
        }
      }
    }

    :param str server_tier: CMDB server tier to connect to.
    One of: "prod", "dev", or "test".  Default is "prod".

    :returns: True on success, otherwise False
    :rtype: bool
    '''
    logger = logging.getLogger(__name__)
    # Setup API connection
    if not _setup_api(server_tier):
        return False
    # Create CMDB class objects
    nisystems_class_name = PILLAR_DATA['nisystems_class']
    patch_audit_class_name = PILLAR_DATA['patch_audit_class']
    try:
        cmdb_classes = {nisystems_class_name:
                        CmdbClass(nisystems_class_name),
                        patch_audit_class_name:
                        CmdbClass(patch_audit_class_name)}
        # Iterate over system records
        for hostname, record in data.items():
            # Skip bad data
            if not isinstance(record, dict):
                msg = 'Bad input data for (%s): %s'
                logger.info(msg, hostname, record)
                continue
            # Iterate over CMDB classes and input data
            for class_id, input_data in record.items():
                # Add card to class
                cmdb_classes[class_id].add_card(input_data)
        # Create/update cards
        for cmdb_class in cmdb_classes.values():
            cmdb_class.update_cards()
    except requests.exceptions.HTTPError as err:
        err_msg = 'HTTPError from (%s) server: %s'
        logger.error(err_msg, server_tier, err)
        return False
    except CmdbClass.Error as err:
        err_msg = 'Class error from (%s) server: %s'
        logger.error(err_msg, server_tier, err)
        return False
    return True


def get_cards(cmdb_class, server_tier='prod'):
    '''
    Retrieve all cards in a CMDB class.

    :param str cmdb_class: CMDB class from which to get card data
    :param str server_tier: CMDB server tier to connect to.
    One of: "prod", "dev", or "test".  Default is "prod".
    :returns: List of dicts, one per card, or empty list on error.
    Errors are logged.
    :rtype: list
    '''
    logger = logging.getLogger(__name__)
    # Setup API connection
    if not _setup_api(server_tier):
        return 'API connection error occurred, see log'
    # Return data default
    ret = []
    try:
        # Create Class object
        class_obj = CmdbClass(cmdb_class)
        # Get cards
        ret.extend(class_obj.get_all_cards())
    except requests.exceptions.HTTPError as err:
        err_msg = 'HTTPError from (%s) server: %s'
        logger.error(err_msg, server_tier, err)
    except CmdbClass.Error as err:
        err_msg = 'Class error from (%s) server: %s'
        logger.error(err_msg, server_tier, err)
    return ret


def delete_cards(card_ids, cmdb_class, server_tier='prod'):
    '''
    Delete cards in a CMDB class.

    :param list card_ids: Numeric IDs of cards to delete
    :param str cmdb_class: CMDB class in which to delete
    :param str server_tier: CMDB server tier to connect to.
    One of: "prod", "dev", or "test".  Default is "prod".
    '''
    logger = logging.getLogger(__name__)
    # Setup API connection
    if not _setup_api(server_tier):
        return 'API connection error occurred, see log'
    try:
        # Create Class object
        class_obj = CmdbClass(cmdb_class)
        # Delete cards
        for card_id in card_ids:
            class_obj.delete_card(card_id)
    except requests.exceptions.HTTPError as err:
        err_msg = 'HTTPError from (%s) server: %s'
        logger.error(err_msg, server_tier, err)
        return False
    except CmdbClass.Error as err:
        err_msg = 'Class error from (%s) server: %s'
        logger.error(err_msg, server_tier, err)
        return False
    return True
