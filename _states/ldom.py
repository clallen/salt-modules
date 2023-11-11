# -*- coding: utf-8 -*-
'''
State module for creating and configuring Solaris guest LDOMs

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

# Python libs
import pprint

# Salt libs
from salt.exceptions import CommandExecutionError


def __virtual__():
    '''
    Can only be run on a T-Series control domain.
    '''
    ctrldom = False
    if 'virtual_subtype' in __grains__:
        if 'control' in __grains__['virtual_subtype']:
            ctrldom = True
    if not ctrldom:
        return False, 'This module can only be run on a T-Series control domain'
    return True


def _vdsvols_absent_data(vdsname, vdsvols):
    if not __opts__['test']:
        data = __salt__['ldm.vdsvols_remove'](vdsname, vdsvols)
    else:
        data = {}
        cur_vdsvols = __salt__['ldm.get_vdsvols'](vdsname)[vdsname]
        cur_names = []
        for vol in cur_vdsvols:
            cur_names.append(vol['vol'])
        data['removed'] = list(set(vdsvols) & set(cur_names))
        data['nonexisting'] = list(set(vdsvols) - set(cur_names))
    return data


def present(name, cpu_arch=None, cores=None, memory=None, domvars=None):
    '''
    Ensure that the specified guest domain exists with the given configuration.
    See ldm(1M).

    :param str name: Guest domain name
    :param str cpu_arch: One of "migration-class1" or "native".
    Can only be changed when the domain is in the inactive state.
    Defaults to "native".
    :param str cores: Number of CPU cores
    :param str memory: Memory with unit notation ("K" or "M" or "G")
    Example: 16G
    :param dict domvars: Domain variables (boot-file, auto-boot?, etc)
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
    changed = {}
    unchanged = {}
    try:
        if not __salt__['ldm.domain_exists'](name):
            # Create new domain
            if not __opts__['test']:
                if cpu_arch is None:
                    cpu_arch = 'native'
                __salt__['ldm.domain_create'](name, cpu_arch)
            changed[name] = 'Created'
        else:
            unchanged[name] = 'Exists'
        constraints = __salt__['ldm.get_domain_constraints'](name)[name]
        # Check cpu-arch
        if cpu_arch is not None:
            if constraints['control']['cpu-arch'] != cpu_arch:
                state = __salt__['ldm.domain_get_state'](name)
                if all([not __opts__['test'], state == 'inactive']):
                    __salt__['ldm.domain_configure'](name, cpu_arch=cpu_arch)
                changed['cpu-arch'] = cpu_arch
            else:
                unchanged['cpu-arch'] = cpu_arch
        # Check cores
        if cores is not None:
            update_cores = False
            if 'core' not in constraints:
                update_cores = True
            elif constraints['core']['count'] != cores:
                update_cores = True
            if update_cores:
                if not __opts__['test']:
                    __salt__['ldm.domain_configure'](name, cores=cores)
                changed['core'] = cores
            else:
                unchanged['core'] = cores
        # Check memory
        if memory is not None:
            cur_mem = int(constraints['memory']['size'])/1024/1024/1024
            unit = memory[-1:]
            if str(cur_mem)+unit != memory:
                if not __opts__['test']:
                    __salt__['ldm.domain_configure'](name, memory=memory)
                changed['memory'] = memory
            else:
                unchanged['memory'] = memory
        # Check domvars
        if domvars is not None:
            cur_vars = __salt__['ldm.get_variable'](name)
            for new_key in domvars:
                val = cur_vars.get(new_key, '')
                # Key exists, value is different
                if val != domvars[new_key]:
                    if 'domvars' not in changed:
                        changed['domvars'] = {new_key: domvars[new_key]}
                    else:
                        changed['domvars'][new_key] = domvars[new_key]
                else:
                    if 'domvars' not in unchanged:
                        unchanged['domvars'] = {new_key: domvars[new_key]}
                    else:
                        unchanged['domvars'][new_key] = domvars[new_key]
            if not __opts__['test']:
                __salt__['ldm.domain_configure'](name, domvars=domvars)
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    # Build changes/comments
    if __opts__['test']:
        comment = []
        if changed:
            comment.append('Would be changed:')
            comment.append(pprint.pformat(changed))
        if unchanged:
            comment.append('Would be unchanged:')
            comment.append(pprint.pformat(unchanged))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if changed:
            changedict['Changed'] = changed
            if unchanged:
                changedict['Unchanged'] = unchanged
    return ret


def absent(name):
    '''
    Ensure the specified guest domain does not exist, along with its VDS
    devices.
    This will force the domain to shutdown and unbind if it is running.

    :param str name: Name of the guest domain
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
        if not __salt__['ldm.domain_exists'](name):
            return ret
        # Get vdisk data before removing domain
        vdisks = __salt__['ldm.get_vdisks'](name)
        # Stop and remove domain
        if not __opts__['test']:
            __salt__['ldm.domain_set_state'](name, 'inactive', force=True)
            __salt__['ldm.domain_remove'](name)
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    # Get VDS volume names from vdisks
    volnames = []
    for vdisk in vdisks:
        volname = vdisk['vol'].split('@')[0]
        volnames.append(volname)
    # Get VDS number
    ordinal = name[-1]
    if ordinal.isdigit():
        vdsnum = str(int(ordinal) - 1)
    else:
        vdsnum = '0'
    # Remove VDS volumes and build result data
    try:
        data = {'removed': [], 'nonexisting': []}
        for vdsname in ['primary-vds'+vdsnum,
                        'secondary-vds'+vdsnum]:
            result = _vdsvols_absent_data(vdsname, volnames)
            if result['removed']:
                data['removed'].append({vdsname: result['removed']})
            if result['nonexisting']:
                data['nonexisting'].append({vdsname: result['nonexisting']})
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    # Build changes/comments
    if __opts__['test']:
        comment = []
        comment.append('Domain would be removed')
        if data['removed']:
            comment.append('Would be removed:')
            comment.append('VDS volumes:')
            comment.append(pprint.pformat(data['removed']))
        if data['nonexisting']:
            comment.append('Nonexistent:')
            comment.append('VDS volumes:')
            comment.append(pprint.pformat(data['nonexisting']))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        changedict['Domain removed'] = name
        if data['removed']:
            changedict['VDS volumes removed'] = data['removed']
            if data['nonexisting']:
                changedict['Nonexistent VDS volumes'] = data['nonexisting']
    return ret


def in_run_state(name, run_state, force=False):
    '''
    Ensure the specified guest domain is in the given run state.

    :param str name: Name of the guest domain
    :param str run_state: One of: "active", "bound", "inactive"
    :param bool force: If True, force shutdown; has no effect with "active"
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
    if not __opts__['test']:
        try:
            changed = __salt__['ldm.domain_set_state'](name, run_state, force)
        except (ValueError, CommandExecutionError) as err:
            ret['result'] = False
            ret['comment'] = str(err)
            return ret
        if changed:
            changedict[name] = run_state
    else:
        cur_state = __salt__['ldm.domain_get_state'](name)
        if cur_state != run_state:
            ret['comment'] = name+' would be set to run state '+run_state
    return ret


def vdsvols_present(name, vdsvols):
    '''
    Ensure the specified VDS volumes exist.

    :param str name: VDS name
    :param list vdsvols: Dicts with keys/values corresponding to the arguments
    of :py:func:`vdsvols_add`:
    ```
    vol: domain1-rootdisk0
    mpgroup: domain1-rootdisk0
    dev: backend device (/dev/dsk/c764r3e...d0s2)
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
    if not __opts__['test']:
        try:
            data = __salt__['ldm.vdsvols_add'](name, vdsvols)
        except CommandExecutionError as err:
            ret['result'] = False
            ret['comment'] = str(err)
            return ret
    else:
        data = {}
        cur_vdsvols = __salt__['ldm.get_vdsvols'](name)[name]
        cur_names = []
        new_names = []
        for vol in cur_vdsvols:
            cur_names.append(vol['vol'])
        for vol in vdsvols:
            new_names.append(vol['vol'])
        data['added'] = list(set(new_names) - set(cur_names))
        data['existing'] = list(set(new_names) & set(cur_names))
    # Build changes/comments
    if __opts__['test']:
        comment = []
        if data['added']:
            comment.append('Would be created:')
            comment.append(pprint.pformat(data['added']))
        if data['existing']:
            comment.append('Existing:')
            comment.append(pprint.pformat(data['existing']))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if data['added']:
            changedict['Created'] = data['added']
            if data['existing']:
                changedict['Existing'] = data['existing']
    return ret


def vdsvols_absent(name, vdsvols):
    '''
    Ensure the specified VDS volumes do not exist.
    If any volumes are in use by vdisks, they will not be removed.
    They will be returned under the "attached" key in the changes dict.

    :param str name: VDS name
    :param list vdsvols: Names of volumes to remove
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
        data = _vdsvols_absent_data(name, vdsvols)
    except CommandExecutionError as err:
        ret['result'] = False
        ret['comment'] = str(err)
        return ret
    # Build changes/comments
    if __opts__['test']:
        comment = []
        if data['removed']:
            comment.append('Would be removed:')
            comment.append(pprint.pformat(data['removed']))
        if data['nonexisting']:
            comment.append('Nonexistent:')
            comment.append(pprint.pformat(data['nonexisting']))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if data['removed']:
            changedict['Removed'] = data['removed']
            if data['nonexisting']:
                changedict['Nonexistent'] = data['nonexisting']
            if data['attached']:
                changedict['Vdisks attached'] = data['attached']
    return ret


def vdisks_present(name, vdisks):
    '''
    Ensure the specified vdisks exist and are attached to the specified domain.

    :param str name: Domain name
    :param list vdisks: List of dicts, each defining a vdisk:
        name: Disk name
        vol: Name of the VDS volume that will back the disk, must be the full
        name, e.g. domain1-rootdisk0@primary-vds1
        id: (optional) vdisk ID. if omitted the next available ID will be used
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
    changed = []
    unchanged = []
    try:
        existing_vdisks = __salt__['ldm.get_vdisks'](name)
        if not existing_vdisks:
            changed = vdisks
        else:
            for existing_vdisk in existing_vdisks:
                for input_vdisk in vdisks:
                    if input_vdisk['name'] == existing_vdisk['name']:
                        unchanged.append(input_vdisk['name'])
            for input_vdisk in vdisks:
                if input_vdisk['name'] not in unchanged:
                    changed.append(input_vdisk)
        if changed:
            if not __opts__['test']:
                __salt__['ldm.vdisks_add'](name, changed)
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    # Build changes/comments
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


def vnets_present(name, vnets):
    '''
    Ensure the specified vnets are attached to the specified domain.

    :param list vnets: List of dicts, each defining a vnet.  These properties
    are required:
        name: vnet name
        vsw: vswitch the vnet is attached to
        pvid: VLAN
    See the add-vnet subcommand in the ldm(1M) man page for other available
    properties.
    :param str name: Domain name
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
    changed = []
    unchanged = []
    try:
        existing_vnets = __salt__['ldm.get_vnets'](name)
        if not existing_vnets:
            changed = vnets
        else:
            for vnet in vnets:
                for existing_vnet in existing_vnets:
                    if vnet['name'] == existing_vnet['name']:
                        unchanged.append(vnet['name'])
                        break
            for vnet in vnets:
                if vnet['name'] not in unchanged:
                    changed.append(vnet)
        if changed:
            if not __opts__['test']:
                __salt__['ldm.vnets_add'](name, changed)
            changedict['Created'] = changed
            if unchanged:
                changedict['Existing'] = unchanged
    except CommandExecutionError as err:
        ret['comment'] = err.message
        ret['result'] = False
    return ret


def vnets_absent(name, vnets):
    '''
    Ensure the specified vnets are not attached to the specified domain.

    :param str name: Domain name
    :param list vnets: List of vnet names
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
    changed = []
    unchanged = []
    try:
        existing_vnets = __salt__['ldm.get_vnets'](name)
        if existing_vnets:
            existing_names = set()
            for existing_vnet in existing_vnets:
                existing_names.add(existing_vnet['name'])
            changed.extend(list(set(vnets) & existing_names))
            unchanged.extend(list(set(vnets) - existing_names))
        if changed:
            if not __opts__['test']:
                __salt__['ldm.vnets_remove'](name, changed)
            changedict['Removed'] = changed
            if unchanged:
                changedict['Nonexistent'] = unchanged
    except CommandExecutionError as err:
        ret['comment'] = err.message
        ret['result'] = False
    return ret
