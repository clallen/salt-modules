# -*- coding: utf-8 -*-
'''
Execution module which provides utility code for common SLS operations

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

# Import python libs
import logging
from collections import OrderedDict


LOG = logging.getLogger(__name__)


def _add_console_msg(message, sls_data, onfail=''):
    '''
    :param str message: Message to convert to timestamped console output command
    :param dict sls_data: Salt SLS data structure
    :param str onfail: Optional state ID to use as an onfail requisite
    :rtype: str
    :returns: The state ID (i.e. console output command) that was added
    '''
    echo_cmd = '/bin/echo "$(/bin/date) '+message+'" >/dev/console'
    if onfail:
        sls_data[echo_cmd] = {'cmd.run': [{'onfail': [onfail]}]}
    else:
        sls_data[echo_cmd] = {'cmd.run': [{'queue': True}]}
    return echo_cmd


def _arg_in_sls(arg_name, sls_data):
    '''
    :param str arg_name: Salt state function argument to find
    :param dict sls_data: Salt SLS data structure
    :rtype: bool
    '''
    args = list(sls_data.values())[0]
    for arg in args:
        if arg_name in arg:
            return True

    return False


def _remove_arg_in_sls(arg_name, sls_data):
    '''
    :param str arg_name: Salt state function argument to remove
    :param dict sls_data: A single Salt state data structure
    :rtype: dict
    :returns: A copy of the input dict with the specified argument removed
    '''
    _ = list(sls_data.values())
    args = _[0]
    new_args = []
    for arg in args:
        if arg_name not in arg:
            new_args.append(arg)
    _ = list(sls_data.keys())
    state_func = _[0]
    return {state_func: new_args}


def console_msg(sls_data, message, prefix='***SALT***', failhard=False):
    '''
    Add a console message to the given SLS data, with the option of a failhard
    state.  This causes the message to be displayed and then terminates the
    state run.

    :param dict sls_data: Standard Salt SLS data
    :param str message: Message to add
    :param str prefix: Prefix for each message
    :param bool failhard: If True, add a `test.fail_without_changes` state with
    the `failhard` option set
    '''
    if prefix:
        msg_out = prefix+' '+message
    else:
        msg_out = message
    if failhard:
        _add_console_msg(msg_out+' - STOPPING', sls_data)
        sls_data['Hard fail on '+message] = {
            'test.fail_without_changes': [
                {'failhard': True}
                ]}
    else:
        _add_console_msg(msg_out, sls_data)


def console_msg_wrap(sls_data, prefix='***SALT***', sf_str=''):
    '''
    Add pre-execution (and conditional post-execution) console notification
    messages to each state operation in the given SLS data (other console
    message states will be skipped).
    Each message consists of a timestamp, a prefix string, and the state ID.
    Post-execution messages are only displayed in the case of execution failure,
    and are suffixed with " - FAILED".
    States with the "failhard" option will have it removed and an additional
    failhard state will be added, in order to have the post-execution message
    displayed.
    This function is generally intended for use with the `config` dict of a
    single SLS file.  For example, replacing `return config` at the end of the
    file with:
    ```
    return __salt__['sls_utils.console_msg_wrap'](config)
    ```
    However it can also be used on any dict containing valid Salt SLS data.

    :param dict sls_data: Standard Salt SLS data
    :param str prefix: Prefix for each message
    :param str sf_str: If non-empty, "Started" and "Finished" messages will be
    prepended and appended to the returned dict.  For example, if the string
    "setup operation" is given, the returned dict will look like this:
    ```
    === Started setup operation ===
    [dict contents]
    === Finished setup operation ===
    ```
    The messages will have the same timestamp and prefix as all other messages.
    :rtype: OrderedDict
    :returns: Standard Salt SLS state structures, i.e.:
    `{
     'State ID1': {'module.function': [arguments]},
     'State ID2': {'module.function': [arguments]}
     }`
    '''
    ret = OrderedDict()
    if not sls_data:
        LOG.warning('Empty dict passed to console_msg_wrap')
        return ret

    if sf_str:
        _add_console_msg(prefix+' === Started '+sf_str+' ===', ret)
    for state_id, state_data in sls_data.items():
        # Skip other console message states
        if state_id.startswith('/bin/echo "$(/bin/date)'):
            continue
        # Check for failhard in input state
        failhard = _arg_in_sls('failhard', state_data)
        # Pre-execution message
        _add_console_msg(prefix+' '+state_id, ret)
        # State ID
        if failhard:
            ret[state_id] = _remove_arg_in_sls('failhard', state_data)
        else:
            ret[state_id] = state_data
        # Post-execution message
        if failhard:
            suffix = '- FAILED - STOPPING'
        else:
            suffix = '- FAILED'
        fail_msg_id = _add_console_msg(prefix+' '+state_id+' '+suffix, ret,
                                       onfail=state_id)
        # Fail state
        if failhard:
            ret['Hard fail on '+state_id] = {
                'test.fail_without_changes': [
                    {'onchanges': [fail_msg_id]},
                    {'failhard': True}
                    ]}
    if sf_str:
        _add_console_msg(prefix+' === Finished '+sf_str+' ===', ret)
    return ret


def editfiles(data, failhard=False, id_str=''):
    '''
    Create SLS execution data for editing files.

    :param dict data: Filenames and operations to be performed on them.
    Structure is a top-level dict with filenames as keys.
    The values are nested dicts with the following structure:
    Keys can be one of the following functions from the `salt.states.file`
    module:
        - uncomment
        - prepend
        - append
    Values are arguments to their respective functions.  These correspond to the
    second argument (usually "text").

    Keys may also be one of the following:
        - replace
        - insert_before
        - insert_after
        - delete
    The value for the `replace` and `insert_` functions is a two-element list:
        - Pattern to find
        - Text to insert or replace with
    For the "delete" key, the value is a pattern matching the line to delete.
    :param bool failhard: If True, set failhard to True in state args.
    Default is False.
    :param str id_str: String to add to generated state IDs, to ensure IDs
    are unique.  Default is empty string.
    :rtype: dict
    :returns: Standard Salt SLS state structures, i.e.:
    ```
    {
    'State ID1': {'module.function': [arguments]},
    'State ID2': {'module.function': [arguments]}
    }
    ```
    '''
    ret = {}
    for filename, ops in data.items():
        for state_func, func_arg in ops.items():
            args = [{'name': filename},
                    {'failhard': failhard}]
            if state_func == 'uncomment':
                args.extend([{'regex': func_arg},
                             {'backup': False}])
            elif any([state_func == 'prepend',
                      state_func == 'append']):
                args.append({'text': func_arg})
            elif state_func == 'replace':
                args.extend([{'pattern': func_arg[0]},
                             {'repl': func_arg[1]},
                             {'backup': False}])
            elif any([state_func == 'insert_before',
                      state_func == 'insert_after']):
                location = state_func.split('_')[1]
                state_func = 'line'
                args.extend([{'mode': 'insert'},
                             {location: func_arg[0]},
                             {'content': func_arg[1]}])
            elif state_func == 'delete':
                state_func = 'line'
                args.extend([{'mode': 'delete'},
                             {'match': func_arg}])
            _ = ''
            if id_str:
                _ = ' for '+id_str
            state_id = 'Editing file '+filename+' '+state_func+_
            ret[state_id] = {'file.'+state_func: args}
    return ret


def nfs_mounts(data, mount=True, failhard=False, id_str=''):
    '''
    Create SLS execution data for mounting NFS shares.

    :param dict data: Mountpoints and related data.
    Structure is a top-level dict with mountpoints as keys.
    The values are nested dicts with the following structure:
    ```
        device: NFS share (server:/share/path)
        opts: Mount options, will be used for mounting and added to (v)fstab.
              If omitted, "defaults" will be used on Linux, "-" will be used on
              Solaris.
    ```
    If the mountpoint does not exist it will be created.
    :param bool mount: If True, mount the shares now, otherwise just add them to
    the (v)fstab.  Default is True.
    :param bool failhard: If True, set failhard to True in state args.
    Default is False.
    :param str id_str: String to add to generated state IDs, to ensure IDs
    are unique.  Default is empty string.
    :rtype: dict
    :returns: Standard Salt SLS state structures, i.e.:
    `{
     'State ID1': {'module.function': [arguments]},
     'State ID2': {'module.function': [arguments]}
     }`
    '''
    ret = {}
    if __grains__['os_family'] == 'RedHat':
        defaults = 'defaults'
        conf = 'fstab'
    else:
        defaults = '-'
        conf = 'vfstab'
    for mountpoint, params in data.items():
        _ = ''
        if id_str:
            _ = ' for '+id_str
        state_id = 'Mounting/adding to '+conf+' NFS mount '+mountpoint+_
        ret[state_id] = {
            'mount.mounted': [
                {'name': mountpoint},
                {'device': params['device']},
                {'fstype': 'nfs'},
                {'mkmnt': True},
                {'mount': mount},
                {'failhard': failhard},
                {'opts': params.get('opts', defaults)}
                ]}
    return ret


def users(data, failhard=False, id_str=''):
    '''
    Create SLS execution data for adding users to the passwd and shadow files.
    Does not create or update homedirs.

    :param dict data: Usernames and related data.
    Structure is a top-level dict with usernames as keys.
    The values are nested dicts with the following structure:
    ```
    uid: Numeric user ID
    gid: Primary user group numeric ID
    homedir: Path to user home directory
    shell: Path to user shell
    ```
    All keys are required.
    :param bool failhard: If True, set failhard to True in state args.
    Default is False.
    :param str id_str: String to add to generated state IDs, to ensure IDs
    are unique.  Default is empty string.
    :rtype: OrderedDict
    :returns: Standard Salt SLS state structures, i.e.:
    `{
     'State ID1': {'module.function': [arguments]},
     'State ID2': {'module.function': [arguments]}
     }`
    '''
    ret = OrderedDict()
    watched_ids = []
    for user, udict in data.items():
        # Append to passwd
        try:
            pw_str = (user+':x:'+udict['uid']+':'+udict['gid']+':'+
                      __grains__['id']+'-'+user+':'+udict['homedir']+':'+
                      udict['shell'])
        except KeyError as err:
            raise ValueError('Key '+str(err)+' missing from input data: '+
                             str(data)) from err

        _ = ''
        if id_str:
            _ = ' for '+id_str
        state_id = 'Verifying '+user+' account in /etc/passwd'+_
        watched_ids.append({'file': state_id})
        ret[state_id] = {
            'file.append': [
                {'name': '/etc/passwd'},
                {'failhard': failhard},
                {'text': pw_str}
                ]}
    # Run pwconv on changes
    users_str = ', '.join(data)
    ret['Running pwconv for passwd changes for users: '+users_str] = {
        'cmd.run': [
            {'name': '/usr/sbin/pwconv'},
            {'failhard': failhard},
            {'onchanges': watched_ids}
            ]}
    return ret


def zpools(data, failhard=False, id_str=''):
    '''
    Create SLS execution data for creating Solaris zpools.

    :param dict data: zpools and related data.
    Structure is a list of dicts.
    Required keys:
    ```
    name: Name of zpool
    device: Backend device node, currently only one is supported (e.g. c1d2)
    ```
    Optional keys:
    ```
    mountpoint: Top-level pool mountpoint
    fs_properties: Dict of zpool properties (see the Properties section in
                   zpool(1M))
    datasets: List of dataset paths, relative to the pool name
              Example: app/grid/product
    delegations: Arguments to "zfs allow" (see the second form of "zfs allow"
                 in zfs_allow(1M))
    volumes: Dict of zvols to create in the pool (name: size)
    ```
    :param bool failhard: If True, set failhard to True in state args.
    Default is False.
    :param str id_str: String to add to generated state IDs, to ensure IDs
    are unique.  Default is empty string.
    :rtype: OrderedDict
    :returns: Standard Salt SLS state structures, i.e.:
    `{
     'State ID1': {'module.function': [arguments]},
     'State ID2': {'module.function': [arguments]}
     }`
    '''
    ret = OrderedDict()
    # Get filesystem_properties, if any
    fs_properties = {}
    if 'mountpoint' in data:
        fs_properties['mountpoint'] = data['mountpoint']
    fs_properties.update(data.get('fs_properties', {}))
    # zpool.present args
    args = [{'name': data['name']},
            {'layout': ['/dev/dsk/'+data['device']]},
            {'config': {'force': True}},
            {'failhard': failhard}]
    if fs_properties:
        args.append({'filesystem_properties': fs_properties})
    ret['Verifying '+data['name']+' zpool'] = {'zpool.present': args}
    # zfs datasets
    for dataset in data.get('datasets', ''):
        _ = ''
        if id_str:
            _ = ' for '+id_str
        ret['Creating zfs dataset '+dataset+_] = {
            'zfs.filesystem_present': [
                {'name': data['name']+'/'+dataset},
                {'create_parent': True},
                {'failhard': failhard}
                ]}
    # zfs volumes
    for volume, size in data.get('volumes', {}).items():
        _ = ''
        if id_str:
            _ = ' for '+id_str
        ret['Creating zfs volume '+volume+_] = {
            'zfs.volume_present': [
                {'name': data['name']+'/'+volume},
                {'volume_size': size},
                {'failhard': failhard}
                ]}
    # Directories
    for directory in data.get('directories', ''):
        _ = ''
        if id_str:
            _ = ' for '+id_str
        ret['Creating directory '+directory+' in data '+data['name']+_] = {
            'file.directory': [
                {'name': data['mountpoint']+'/'+directory},
                {'makedirs': True},
                {'failhard': failhard}
                ]}
    # Delegations
    for delegation in data.get('delegations', ''):
        _ = ''
        if id_str:
            _ = ' for '+id_str
        ret['Setting zfs delegation '+delegation+_] = {
            'cmd.run': [
                {'name': '/usr/sbin/zfs '+delegation+' '+data['name']},
                {'failhard': failhard}
                ]}
    return ret


def get_sls_logger(logname):
    '''
    Get an instance of a file logger for writing debug output from SLS
    rendering.
    The file will be named ```[logname].log```, and created in the dir
    specified in pillar (salt:sls_logdir).  By default this is
    "/var/tmp/sls_logs".
    An existing log of the same name will be overwritten.

    :param str logname: Name to use in the %(name) log field (usually __name__
    from the caller)
    :returns: A file logger
    '''
    logdir = __salt__['pillar.get']('salt:sls_logdir')
    try:
        __salt__['file.mkdir'](logdir)
    except OSError:
        __salt__['file.remove'](logdir)
        __salt__['file.mkdir'](logdir)
    if logname in logging.Logger.manager.loggerDict:
        del logging.Logger.manager.loggerDict[logname]
    filename = logdir+'/'+logname+'.log'
    format_str = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    logger = logging.getLogger(logname)
    handler = logging.FileHandler(filename, mode='w')
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(fmt=format_str))
    logger.addHandler(handler)
    return logger
