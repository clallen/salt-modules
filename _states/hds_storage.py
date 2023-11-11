# -*- coding: utf-8 -*-
'''
State module for working with Hitachi SAN storage

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''
from __future__ import absolute_import

# Python libs
import re
import pprint

# Salt libs
from salt.exceptions import CommandExecutionError


def ldevs_created(name, inst, ldev_ids, capacity, name_index=1):
    '''
    Ensure that the specified LDEVs exist.

    :param str name: Base LDEV name.  Each LDEV will have this name, appended
    with a sequential index (i.e. NAME_01, NAME_02, etc.).  See name_index arg.
    Must be alphanumeric, can contain underscores and hyphens.
    :param str inst: HORCM instance number
    :param list ldev_ids: LDEV ID strings
    :param str capacity: Capacity (in GB) of each LDEV
    :param str name_index: Number at which sequential name indexes start,
    default is 1.
    '''
    changedict = {}
    ret = {'name': name,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    str_inst = str(inst)
    try:
        if not __opts__['test']:
            data = __salt__['hds_cci.create_ldevs'](str_inst, name,
                                                    ldev_ids, str(capacity),
                                                    name_index=int(name_index))
        else:
            metadata = __salt__['hds_cci.get_ldevs_metadata'](str_inst,
                                                              ldev_ids)
    except (LookupError, ValueError, CommandExecutionError) as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    if __opts__['test']:
        # Calculate what would be created and what already exists
        data = {}
        for ldev_id, mdict in metadata.items():
            if mdict:
                data[ldev_id] = 'exists'
            else:
                data[ldev_id] = 'success'
    # Build changes lists
    changed = []
    unchanged = []
    for ldev_id, status in data.items():
        if status == 'success':
            changed.append(ldev_id)
        else:
            unchanged.append(ldev_id)
    if __opts__['test']:
        comment = []
        if changed:
            comment.append('Would be created:')
            comment.append(pprint.pformat(changed))
        if unchanged:
            comment.append('Existing:')
            comment.append(pprint.pformat(unchanged))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if changed:
            changedict['Created'] = changed
            if unchanged:
                changedict['Existing'] = unchanged
    return ret


def ldevs_deleted(name, inst, ldev_ids):
    '''
    Ensure that the specified LDEVs are deleted.

    :param str name: Salt state name
    :param str inst: HORCM instance number
    :param list ldev_ids: LDEV ID strings
    '''
    changedict = {}
    ret = {'name': name,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    try:
        if not __opts__['test']:
            data = __salt__['hds_cci.delete_ldevs'](str(inst), ldev_ids)
        else:
            metadata = __salt__['hds_cci.get_ldevs_metadata'](str(inst),
                                                              ldev_ids)
    except (ValueError, CommandExecutionError) as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    if __opts__['test']:
        # Calculate what would be deleted,
        # what is already deleted,
        # and what can't be deleted because it is shared
        data = {}
        for ldev_id, mdict in metadata.items():
            # LDEV not defined
            if not mdict:
                data[ldev_id] = 'does not exist'
                continue
            # LDEV shared, can't delete
            if mdict['sharing']:
                data[ldev_id] = 'shared'
                continue
            # LDEV would be deleted
            data[ldev_id] = 'success'
    # Build changes dicts
    changed = {}
    unchanged = {}
    for ldev_id, status in data.items():
        if status == 'success':
            changed[ldev_id] = 'Deleted'
        elif status == 'shared':
            unchanged[ldev_id] = 'Not deleted, is shared'
        else:
            unchanged[ldev_id] = 'Does not exist'
    if __opts__['test']:
        comment = []
        if changed:
            comment.append('Would be deleted:')
            comment.append(pprint.pformat(changed))
        if unchanged:
            comment.append('Would not be deleted:')
            comment.append(pprint.pformat(unchanged))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if changed:
            changedict['Deleted'] = changed
            if unchanged:
                changedict['Not deleted'] = unchanged
    return ret


def ldevs_shared(name, inst, ldev_ids, ports, hosts):
    '''
    Ensure that the specified LDEVs are shared to the specified hosts, on the
    specified ports.

    :param str name: Salt state name
    :param str inst: HORCM instance number
    :param list ldev_ids: LDEV ID strings
    :param list ports: SAN ports
    :param list hosts: SAN hosts
    '''
    changedict = {}
    ret = {'name': name,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    str_inst = str(inst)
    try:
        if not __opts__['test']:
            data = __salt__['hds_cci.share_ldevs'](str_inst, ldev_ids,
                                                   ports, hosts)
        else:
            metadata = __salt__['hds_cci.get_ldevs_metadata'](str_inst,
                                                              ldev_ids)
    except (ValueError, CommandExecutionError) as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    if __opts__['test']:
        # Calculate what would be shared,
        # and what is already shared
        data = {}
        for ldev_id, mdict in metadata.items():
            # LDEV not defined
            if not mdict:
                data[ldev_id] = {}
                continue
            shared = {}
            existing = {}
            data[ldev_id] = {'shared': shared, 'existing': existing}
            cur_sharing = mdict['sharing']
            for port in ports:
                # Validate port
                if re.match(r'CL\d{1}-[a-z]{1}', port, re.I) is None:
                    shared[port] = 'Invalid port, skipping'
                    continue
                # This port is not shared on: all hosts would be shared on it
                if port not in cur_sharing:
                    shared[port] = hosts
                # This port is shared on:
                # difference of hosts would be shared
                # intersection of hosts is already shared
                else:
                    cur_shared_hosts = set(cur_sharing[port])
                    new_shared_hosts = set(hosts) - cur_shared_hosts
                    existing_hosts = set(hosts) & cur_shared_hosts
                    if new_shared_hosts:
                        shared[port] = new_shared_hosts
                    if existing_hosts:
                        existing[port] = existing_hosts
    # Build changes dicts
    changed = {}
    unchanged = {}
    for ldev_id, sdict in data.items():
        if not sdict:
            unchanged[ldev_id] = 'Does not exist'
        else:
            if sdict['shared']:
                changed[ldev_id] = sdict['shared']
            if sdict['existing']:
                unchanged[ldev_id] = sdict['existing']
    if __opts__['test']:
        comment = []
        if changed:
            comment.append('Would be shared:')
            comment.append(pprint.pformat(changed))
        if unchanged:
            comment.append('Would not be shared:')
            comment.append(pprint.pformat(unchanged))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if changed:
            changedict['Shared'] = changed
            if unchanged:
                changedict['Not shared'] = unchanged
    return ret


def ldevs_unshared(name, inst, ldev_ids, ports=None, hosts=None):
    '''
    Ensure that the specified LDEVs are unshared from the specified hosts.

    :param str name: Salt state name
    :param str inst: HORCM instance number
    :param list ldev_ids: LDEV ID strings
    :param list ports: SAN ports.  If None, unshare on all ports.
    :param list hosts: SAN hosts.  If None, unshare from all hosts.
    '''
    changedict = {}
    ret = {'name': name,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    str_inst = str(inst)
    try:
        if not __opts__['test']:
            data = __salt__['hds_cci.unshare_ldevs'](str_inst, ldev_ids,
                                                     ports, hosts)
        else:
            metadata = __salt__['hds_cci.get_ldevs_metadata'](str_inst,
                                                              ldev_ids)
    except (ValueError, CommandExecutionError) as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    if __opts__['test']:
        # Build port and host lists if not given
        if ports is None:
            tmp = set()
            for mdict in metadata.values():
                if not mdict:
                    continue
                cur_sharing = mdict['sharing']
                tmp.update(set(cur_sharing.keys()))
            ports = list(tmp)
        if hosts is None:
            tmp = set()
            for mdict in metadata.values():
                if not mdict:
                    continue
                cur_sharing = mdict['sharing']
                for _ in cur_sharing.values():
                    tmp.update(set(_))
            hosts = list(tmp)
        # Calculate what would be unshared,
        # and what would already be unshared
        data = {}
        for ldev_id, mdict in metadata.items():
            # LDEV not defined
            if not mdict:
                data[ldev_id] = {}
                continue
            unshared = {}
            existing = {}
            data[ldev_id] = {'unshared': unshared, 'existing': existing}
            cur_sharing = mdict['sharing']
            for port in ports:
                # Validate port
                if re.match(r'CL\d{1}-[a-z]{1}', port, re.I) is None:
                    existing[port] = 'Invalid port, skipping'
                    continue
                # This port is not shared on: all hosts already unshared
                if port not in cur_sharing:
                    existing[port] = hosts
                # This port is shared on:
                # difference of hosts is already unshared
                # intersection of hosts would be unshared
                else:
                    cur_shared_hosts = set(cur_sharing[port])
                    new_unshared_hosts = set(hosts) & cur_shared_hosts
                    existing_hosts = set(hosts) - cur_shared_hosts
                    if new_unshared_hosts:
                        unshared[port] = list(new_unshared_hosts)
                    if existing_hosts:
                        existing[port] = list(existing_hosts)
    # Build changes dicts
    changed = {}
    unchanged = {}
    for ldev_id, sdict in data.items():
        if not sdict:
            unchanged[ldev_id] = 'Not shared'
        else:
            if sdict['unshared']:
                changed[ldev_id] = sdict['unshared']
            if sdict['existing']:
                unchanged[ldev_id] = sdict['existing']
    if __opts__['test']:
        comment = []
        if changed:
            comment.append('Would be unshared:')
            comment.append(pprint.pformat(changed))
        if unchanged:
            comment.append('Would not be unshared:')
            comment.append(pprint.pformat(unchanged))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if changed:
            changedict['Shared'] = changed
            if unchanged:
                changedict['Not shared'] = unchanged
    return ret


def cmddev_allocated(name, inst, ldev_id):
    '''
    Allocate the given LDEV ID as a command device on the specified
    frame.

    :param str name: Device label basename; "-cmd" will be appended
    :param str inst: HORCM instance number
    :param str ldev_id: LDEV ID to allocate
    '''
    changedict = {}
    comments = []
    ret = {'name': name,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    str_inst = str(inst)
    changed = {}
    unchanged = {}
    try:
        cmddev_name = name+'-cmd'
        # Look for already defined cmddev
        metadata = __salt__['hds_cci.get_ldevs_metadata'](inst, [ldev_id])
        # If not found, create
        if not metadata.get(ldev_id, ''):
            if not __opts__['test']:
                # Allocate
                __salt__['hds_cci.create_ldevs'](str_inst, cmddev_name,
                                                 [ldev_id], '48', in_mb=True,
                                                 name_index=None)
                # Flip cmddev switch
                __salt__['hds_cci.enable_cmddev'](str_inst, ldev_id)
            changed[cmddev_name] = ldev_id
        else:
            unchanged[cmddev_name] = ldev_id
    except (ValueError, LookupError, CommandExecutionError) as err:
        ret['comment'] = str(err)
        ret['result'] = False
    if __opts__['test']:
        if changed:
            comments.append('Would be created')
            comments.append(pprint.pformat(changed))
        if unchanged:
            comments.append('Existing')
            comments.append(pprint.pformat(unchanged))
    else:
        if changed:
            changedict['Created'] = changed
            if unchanged:
                changedict['Existing'] = unchanged
    return ret


def horcm_svcinst_configured(name, inst):
    '''
    Ensure that the HORCM SMF service instance is configured.

    :param str name: Salt state name
    :param str inst: HORCM instance number
    '''
    changedict = {}
    ret = {'name': name,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    str_inst = str(inst)
    if __salt__['hds_cci.horcminst_exists'](str_inst):
        ret['comment'] = 'horcm'+str_inst+' SMF service already exists'
        return ret
    if not __opts__['test']:
        try:
            __salt__['hds_cci.setup_horcminst'](str_inst)
            changedict['Configured'] = 'horcm'+str_inst+' SMF service'
        except CommandExecutionError as err:
            ret['comment'] = str(err)
            ret['result'] = False
    else:
        ret['comment'] = 'horcm'+str_inst+' SMF service would be configured'
    return ret


def horcm_conf_present(name, inst, disk_groups=None, exclude=None, force=False):
    '''
    Ensure that a HORCM config file is set up for the specified instance.

    :param str name: Hostname to use in HORCM_MON section
    :param str inst: HORCM instance number
    :param list disk_groups: Patterns to match in disk groups shared to this
    host (see :py:func:`find_ldev_ids` in the hds_cci execution module).
    If None, a "bare" config will be written.
    :param str exclude: LDEV names containing this string will be excluded
    :param bool force: If True, overwrite existing file
    '''
    changedict = {}
    ret = {'name': name,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    str_inst = str(inst)
    exists = __salt__['hds_cci.horcmconf_exists'](str_inst)
    if all([exists, not force]):
        ret['comment'] = 'horcm'+str_inst+' config file already exists'
        return ret
    if not __opts__['test']:
        try:
            groups = []
            if disk_groups is not None:
                si_host = __salt__['pillar.get']('san:si_host')
                for disk_group in disk_groups:
                    ldevs = __salt__['hds_cci.find_ldev_ids'](disk_group)
                    groups.append({'name': disk_group,
                                   'devices': ldevs,
                                   'rhost': si_host,
                                   'rinst': str_inst,
                                   'exclude': exclude})
            __salt__['hds_cci.horcmconf_write'](str_inst, name, data=groups)
            changedict['Written'] = 'horcm'+str_inst+' config file'
        except CommandExecutionError as err:
            ret['comment'] = str(err)
            ret['result'] = False
    else:
        ret['comment'] = 'horcm'+str_inst+' config file would be written'
    return ret


def hostgroups_exist(name, inst, port, hosts_to_wwns):
    '''
    Ensure that the specified hostgroups exist on the specified port.

    :param str name: Salt state name
    :param str inst: HORCM instance number
    :param str port: SAN port
    :param dict hosts_to_wwns: Structure:
    ```
    hostname1:
      - WWN1
      - WWN2
      - WWN3
    hostname2:
      - WWN1
      - WWN2
      - WWN3
    ```
    '''
    changedict = {}
    ret = {'name': name,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    # Validate port
    if re.match(r'CL\d{1}-[a-z]{1}', port, re.I) is None:
        ret['comment'] = 'Invalid port format: '+port
        ret['result'] = False
        return ret
    try:
        hostgroups = __salt__['hds_cci.get_hostgroups'](inst, port)
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    changed = {}
    unchanged = {}
    for host, wwns in hosts_to_wwns.items():
        if host in hostgroups:
            unchanged[host] = wwns
            continue
        if not __opts__['test']:
            try:
                __salt__['hds_cci.add_hostgroup'](inst, port, host, wwns)
            except CommandExecutionError as err:
                ret['comment'] = str(err)
                ret['result'] = False
                return ret
        changed[host] = wwns
    if __opts__['test']:
        comment = []
        if changed:
            comment.append('Would be created:')
            comment.append(pprint.pformat(changed))
        if unchanged:
            comment.append('Would not be created:')
            comment.append(pprint.pformat(unchanged))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if unchanged:
            changedict['Not created'] = unchanged
        if changed:
            changedict['Created'] = changed
    return ret
