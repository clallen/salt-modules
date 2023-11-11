# -*- coding: utf-8 -*-
'''
Execution module for Solaris Logical Domain Manager command-line tool (ldm)

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

# Import Python libs
import logging
import copy
import fnmatch
from collections import OrderedDict

# Import Salt libs
from salt.exceptions import CommandExecutionError

LDM = '/usr/sbin/ldm'


def __virtual__():
    '''
    Only run on T-Series SPARC control domain
    '''
    if all([__grains__['cpu_model'] != 'SPARC-T4',
            __grains__['cpu_model'] != 'SPARC-T5',
            __grains__['cpu_model'] != 'SPARC-M7']):
        return False, 'This module must be run on T-Series SPARC.'
    if 'control' not in __salt__['grains.get']('virtual_subtype'):
        return False, 'This module must be run on an LDOMs control domain.'
    return True


def domain_exists(domname):
    '''
    Check to see if the domain exists.

    :param str domname: Domain name
    :rtype: bool
    '''
    ret = __salt__['cmd.retcode'](LDM+' list '+domname,
                                  output_loglevel='quiet')
    return not bool(ret)


def domain_get_state(domname):
    '''
    Return current domain state.

    :param str domname: Domain name
    :rtype: str
    :returns: One of "active", "bound", "inactive", or "unknown"
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' list -p '+domname,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying state for domain "'+
                                    domname+'"', info=ret['stderr'])
    state = 'unknown'
    for item in ret['stdout'].split('|'):
        if item.startswith('state'):
            state = item.split('=')[1]
    return state


def domain_set_state(domname, state, force=False):
    '''
    Set domain state.

    :param str domname: Domain name
    :param str state: One of "active", "bound", or "inactive"
    :param bool force: If True, force shutdown; has no effect with "active"
    :rtype: bool
    :returns: True if state changed, False if no change
    :raises: CommandExecutionError: Problem running a shell command
    :raises: ValueError: Invalid state arg
    '''
    # validate input
    if all([state != 'active',
            state != 'bound',
            state != 'inactive']):
        raise ValueError('Invalid state arg: '+state)

    if force:
        stopcmd = ' stop -f '
    else:
        stopcmd = ' stop '
    cstate = domain_get_state(domname)
    if state == cstate:
        return False

    if state == 'active':
        if cstate == 'inactive':
            ret = __salt__['cmd.run_all'](LDM+' bind '+domname,
                                          output_loglevel='quiet')
            if ret['retcode'] != 0:
                raise CommandExecutionError('Error binding domain "'+domname+
                                            '"', info=ret['stderr'])
        ret = __salt__['cmd.run_all'](LDM+' start '+domname,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error starting domain "'+domname+'"',
                                        info=ret['stderr'])
    elif state == 'bound':
        if cstate == 'active':
            ret = __salt__['cmd.run_all'](LDM+stopcmd+domname,
                                          output_loglevel='quiet')
            if ret['retcode'] != 0:
                raise CommandExecutionError('Error stopping domain "'+domname+
                                            '"', info=ret['stderr'])
        else:
            ret = __salt__['cmd.run_all'](LDM+' bind '+domname,
                                          output_loglevel='quiet')
            if ret['retcode'] != 0:
                raise CommandExecutionError('Error binding domain "'+domname+
                                            '"', info=ret['stderr'])
    elif state == 'inactive':
        if cstate == 'active':
            ret = __salt__['cmd.run_all'](LDM+stopcmd+domname,
                                          output_loglevel='quiet')
            if ret['retcode'] != 0:
                raise CommandExecutionError('Error stopping domain "'+domname+
                                            '"', info=ret['stderr'])
        ret = __salt__['cmd.run_all'](LDM+' unbind '+domname,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error unbinding domain "'+domname+'"',
                                        info=ret['stderr'])
    return True


def domain_create(domname, cpu_arch):
    '''
    Create guest domain.

    :param str domname: Domain name
    :param str cpu_arch: Either **migration-class1** or **native**
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' add-domain cpu-arch='+cpu_arch+' '+
                                  domname, output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error creating domain "'+domname+'"',
                                    info=ret['stderr'])


def domain_remove(domname):
    '''
    Remove guest domain.

    :param str domname: Domain name
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' rm-domain '+domname,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error removing domain "'+domname+'"',
                                    info=ret['stderr'])


def domain_configure(domname, **props):
    '''
    Configure various properties of a guest domain.

    :param str domname: Domain name
    :param kwargs props: Properties to change.  Allowed keywords:
      * cpu_arch: Either "migration-class1" or "native"
      * cores: Number of CPU cores
      * memory: Memory with unit notation ("K" or "M" or "G").  Example: 16G
      * domvars: Dict of domain variables.  Existing values are overwritten, if
      a value is an empty str, the key/value will be deleted.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    if 'cpu_arch' in props:
        ret = __salt__['cmd.run_all'](LDM+' set-domain cpu-arch='+
                                      props['cpu_arch']+' '+domname,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error setting CPU arch on domain "'+
                                        domname+'"', info=ret['stderr'])
    if 'cores' in props:
        ret = __salt__['cmd.run_all'](LDM+' set-core '+props['cores']+' '+
                                      domname, output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error setting CPU cores on domain "'+
                                        domname+'"', info=ret['stderr'])
    if 'memory' in props:
        mem = props['memory'].upper()
        if not any([mem.endswith('K'), mem.endswith('M'), mem.endswith('G')]):
            raise ValueError('Invalid memory specification: '+props['memory'])
        ret = __salt__['cmd.run_all'](LDM+' set-memory --auto-adj '+
                                      props['memory']+' '+domname,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error setting memory on domain "'+
                                        domname+'"', info=ret['stderr'])
    if 'domvars' in props:
        for key, val in props['domvars'].items():
            if not val:
                ret = __salt__['cmd.run_all'](LDM+' rm-var '+key+' '+domname,
                                              output_loglevel='quiet')
                if ret['retcode'] != 0:
                    raise CommandExecutionError('Error removing variable from '+
                                                'domain "'+domname+'"',
                                                info=ret['stderr'])
            else:
                ret = __salt__['cmd.run_all'](LDM+' set-var '+key+'="'+val+'" '+
                                              domname, output_loglevel='quiet')
                if ret['retcode'] != 0:
                    raise CommandExecutionError('Error setting variable in '+
                                                'domain "'+domname+'"',
                                                info=ret['stderr'])


def vnet_set(domname, vnet, key, value):
    '''
    Set a vnet property.  Key/value must correspond to a property in the
    "set-vnet" section of ldm(1M).

    :param str domname: Domain name
    :param str vnet: vnet to change
    :param str key: Key of property to set
    :param str value: Value of property to set
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' set-vnet '+key+'='+value+' '+
                                  vnet+' '+domname, output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error setting property "'+key+'='+value+
                                    '" on vnet "'+vnet+'" on domain "'+
                                    domname+'"', info=ret['stderr'])


def vsw_set(vswname, key, value):
    '''
    Set a vswitch property.  Key/value must correspond to a property in the
        "set-vswitch" section of ldm(1M).

    :param str vswname: vswitch to change
    :param str key: Key of property to set
    :param str value: Value of property to set
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' set-vsw '+key+'='+value+' '+
                                  vswname, output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error setting property "'+key+'='+value+
                                    '" on vswitch "'+vswname,
                                    info=ret['stderr'])


def vdsvols_add(vdsname, vdsvols):
    '''
    Add VDS volumes.

    :param str vdsname: Name of the VDS to use (e.g. "primary-vds1")
    :param list vdsvols: List of dicts, each defining a VDS volume:
    * vol: volume name
    * mpgroup: multipath group
    * dev: backend device
    :rtype: dict
    :returns: Results of adding attempts:
    ```
    'added':
      - volume name
    'existing':
      - volume name
    ```
    Top-level keys will always be returned, but list values will be empty if
    nothing added/existing.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = {'added': [], 'existing': []}
    for vdsvol in vdsvols:
        out = __salt__['cmd.run_all'](LDM+' add-vdsdev -f mpgroup='+
                                      vdsvol['mpgroup']+' '+vdsvol['dev']+' '+
                                      vdsvol['vol']+'@'+vdsname,
                                      output_loglevel='quiet')
        if out['retcode'] and 'already exists' not in out['stderr']:
            raise CommandExecutionError('Error adding vdsvol '+vdsvol['vol']+
                                        ' to VDS '+vdsname, info=out['stderr'])

        if 'already exists' in out['stderr']:
            ret['existing'].append(vdsvol['vol'])
        else:
            ret['added'].append(vdsvol['vol'])
    return ret


def vdsvols_remove(vdsname, vdsvols):
    '''
    Remove VDS volumes.
    If any volumes are in use by vdisks, they will not be removed.
    They will be returned under the "attached" key in the return data.

    :param str vdsname: VDS name
    :param list vdsvol: Names of volumes to remove
    :rtype: dict
    :returns: Results of removal attempts:
    ```
    'removed':
      - volume name
    'nonexisting':
      - volume name
    'attached':
      - volume name
    ```
    Top-level keys will always be returned, but list values will be empty if
    nothing removed/nonexisting/attached.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = {'removed': [],
           'nonexisting': [],
           'attached': []}
    for vdsvol in vdsvols:
        out = __salt__['cmd.run_all'](LDM+' rm-vdsdev '+vdsvol+'@'+vdsname,
                                      output_loglevel='quiet')
        if all([out['retcode'],
                'does not exist' not in out['stderr'],
                'is attached' not in out['stderr']]):
            raise CommandExecutionError('Error removing vdsvol '+
                                        vdsvol+'@'+vdsname,
                                        info=out['stderr'])

        if 'does not exist' in out['stderr']:
            ret['nonexisting'].append(vdsvol)
        elif 'is attached' in out['stderr']:
            ret['attached'].append(vdsvol)
        else:
            ret['removed'].append(vdsvol)
    return ret


def vdisks_add(domname, vdisks):
    '''
    Add vdisks to the specified domain.

    :param str domname: Domain name
    :param list vdisks: List of dicts, each defining a vdisk:
    * name: Disk name
    * vol: Name of the volume that will back the disk, must be the full name,
      e.g. domain1-rootdisk0@primary-vds1
    * id: (optional) vdisk ID. if omitted the next highest multiple of 10 will
      be used for the first disk in the list, incrementing by 1 for the rest.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    # get next highest disk ID in multiple of 10
    highest_id = '0'
    for disk in get_vdisks(domname):
        if int(disk['id']) > 89:
            break
        if int(disk['id']) > int(highest_id):
            highest_id = disk['id']
    incr_id = int(highest_id)+(10-int(highest_id) % 10)
    for vdisk in vdisks:
        if 'id' in vdisk:
            vid = str(vdisk['id'])
        else:
            vid = str(incr_id)
            incr_id += 1
        ret = __salt__['cmd.run_all'](LDM+' add-vdisk id='+vid+' '+
                                      vdisk['name']+' '+vdisk['vol']+' '+
                                      domname, output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error adding vdisk '+vdisk['name']+
                                        ' to guest '+domname,
                                        info=ret['stderr'])


def vdisks_remove(domname, vdisks):
    '''
    Remove a vdisk from the specified domain.

    :param str domname: Domain name
    :param list vdisks: Names of vdisks to remove
    :raises: CommandExecutionError: Problem running a shell command
    '''
    for name in vdisks:
        ret = __salt__['cmd.run_all'](LDM+' rm-vdisk '+name+' '+domname,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error removing vdisk '+name+
                                        ' from guest '+domname,
                                        info=ret['stderr'])


def vnets_add(domname, vnets):
    '''
    Add vnets to the specified domain.

    :param str domname: Domain name
    :param list vnets: List of dicts, each defining a vnet.  These properties
    are required:
        name: vnet name
        vsw: vswitch the vnet is attached to
        pvid: VLAN
    See the add-vnet subcommand in the ldm(1M) man page for other available
    properties.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    for vnet in copy.deepcopy(vnets):
        name = vnet.pop('name')
        vsw = vnet.pop('vsw')
        args = ['pvid='+vnet.pop('pvid'), 'linkprop=phys-state']
        if vnet:
            for prop, val in vnet.items():
                args.append(prop+'='+val)
        ret = __salt__['cmd.run_all'](LDM+' add-vnet '+' '.join(args)+
                                      ' '+name+' '+vsw+' '+domname,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error adding vnet '+vnet['name']+
                                        ' to guest '+domname,
                                        info=ret['stderr'])


def vnets_remove(domname, vnets):
    '''
    Remove vnets from the specified domain.

    :param str domname: Domain name
    :param list vnets: List of vnet names
    :raises: CommandExecutionError: Problem running a shell command
    '''
    for vnet in vnets:
        ret = __salt__['cmd.run_all'](LDM+' rm-vnet '+vnet+' '+domname,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error removing vnet '+vnet+
                                        ' from guest '+domname,
                                        info=ret['stderr'])


def get_variable(domname, varname=None):
    '''
    Get domain variable(s).

    :param str domname: Domain name
    :param str varname: Variable key name.  If None, return all variables.
    :rtype: dict
    :returns: Key/value domain variables, empty dict if specified variable key
    does not exist
    :raises: CommandExecutionError: Problem running a shell command
    '''
    if varname is None:
        ret = __salt__['cmd.run_all'](LDM+' list-variable '+domname,
                                      output_loglevel='quiet')
    else:
        ret = __salt__['cmd.run_all'](LDM+' list-variable '+varname+' '+domname,
                                      output_loglevel='quiet')
    if 'not found' in ret['stderr']:
        return {}
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying variable '+varname+
                                    ' for domain "'+domname+'"',
                                    info=ret['stderr'])
    retdict = {}
    for line in ret['stdout'].splitlines():
        if '=' not in line:
            continue
        var = line.split('=', 1)
        retdict[var[0]] = var[1]
    return retdict


def get_vnets(domname):
    '''
    Get virtual network device information.

    :param str domname: Domain name
    :rtype: list
    :returns: A list of dicts, one per vnet, empty if none found.  See the "-o"
    option section of the "list-domain" subcommand in ldm(1M) for details.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' list-domain -o net -p '+domname,
                                  output_loglevel='quiet')
    if ret['retcode'] > 1:
        raise CommandExecutionError('Error querying network devices '+
                                    ' on guest '+domname, info=ret['stderr'])
    retlist = []
    for line in ret['stdout'].splitlines():
        if not line.startswith('VNET'):
            continue
        items = line.split('|')
        items.pop(0)
        ddict = {}
        for item in items:
            key, val = item.split('=')
            ddict[key] = val
        retlist.append(ddict)
    return retlist


def get_netdevs(domname):
    '''
    Get network device information.  This is output from the "ldm list-netdev"
    command.

    :param str domname: Domain name
    :rtype: list
    :returns: A list of dicts, one per netdev, empty if none found.  See the
    "-o" option section of the "list-domain" subcommand in ldm(1M) for details.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' list-netdev -l -p '+domname,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying netdevs on guest '+
                                    domname, info=ret['stderr'])
    retlist = []
    in_aggr = False
    aggr_ddict = {}
    for line in ret['stdout'].splitlines():
        if line.startswith('DOMAIN'):
            continue
        items = line.split('|')
        if all([in_aggr, not line.startswith('|')]):
            in_aggr = False
        if all([not in_aggr, 'class=AGGR' in line]):
            in_aggr = True
            aggr_ddict.clear()
            for item in items:
                key, val = item.split('=')
                aggr_ddict[key] = val
            aggr_ddict['members'] = []
            retlist.append(aggr_ddict)
        elif not in_aggr:
            ddict = {}
            for item in items:
                key, val = item.split('=')
                ddict[key] = val
            retlist.append(ddict)
        else:
            member = {}
            items.pop(0)
            for item in items:
                key, val = item.split('=')
                member[key] = val
            aggr_ddict['members'].append(member)
    return retlist


def get_vdisks(domname):
    '''
    Get virtual disk information.

    :param str domname: Domain name
    :rtype: list
    :returns: A list of dicts, one per vdisk, empty if none found. All values
    are of type str.  See the "-o" option section of the "list-domain"
    subcommand in ldm(1M) for details.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' list-domain -o disk -p '+domname,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying vdisks on guest '+
                                    domname, info=ret['stderr'])
    retlist = []
    for line in ret['stdout'].splitlines():
        if not line.startswith('VDISK'):
            continue
        items = line.split('|')
        items.pop(0)
        ddict = {}
        for item in items:
            key, val = item.split('=')
            ddict[key] = val
        retlist.append(ddict)
    return retlist


def get_vdsvols(vdsname=None):
    '''
    Get VDS volume information.

    :param str vdsname: VDS to return data from, if None return data from all
    :rtype: dict
    :returns: Key: VDS name, Value: list of dicts of VDS data, empty if none
    found.  See the "list-services" section of ldm(1M) for details.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' list-services -p',
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying virtual services',
                                    info=ret['stderr'])
    cur_vds = ''
    retdict = {}
    for line in ret['stdout'].splitlines():
        if line.startswith('VDS'):
            cur_vds = line.split('|')[1].split('=')[1]
            if vdsname is not None:
                if cur_vds != vdsname:
                    continue
            retdict[cur_vds] = []
        elif line.startswith('|vol'):
            if vdsname is not None:
                if cur_vds != vdsname:
                    continue
            vol = {}
            for prop in line.split('|'):
                keyval = prop.split('=')
                if not keyval[0]:
                    continue
                if len(keyval) == 2:
                    vol[keyval[0]] = keyval[1]
                else:
                    vol[keyval[0]] = ''
            retdict[cur_vds].append(vol)
    return retdict


def get_vsws():
    '''
    Get virtual switch information.

    :rtype: dict
    :returns: Key: vswitch name, Value: dict of vswitch properties, empty if
    none found.  See the "list-services" section of ldm(1M) for details.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' ls-services -p',
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying vswitches',
                                    info=ret['stderr'])
    retdict = {}
    for line in ret['stdout'].splitlines():
        if not line.startswith('VSW'):
            continue
        items = line.split('|')
        items.pop(0)
        for item in items:
            key, val = item.split('=')
            if key == 'name':
                name = val
                retdict[name] = {}
                continue
            if key == 'vid':
                retdict[name]['vid'] = val.split(',')
                continue
            retdict[name][key] = val
    return retdict


def get_domains(state='all', guests_only=False):
    '''
    Get domains on this chassis and their current state.

    :param str state: Only return domains with this state.  One of: 'active',
    'inactive', 'bound', 'all'.  Default is 'all'.
    :param bool guests_only: If True, get only guest LDOM data (no control or
    service domains).  Default is False.
    :rtype: dict
    :returns: A dict with domain name as key, dict of domain properties as value
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' list-domain -p',
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying domains',
                                    info=ret['stderr'])
    retdict = {}
    for line in ret['stdout'].splitlines():
        if not line.startswith('DOMAIN'):
            continue
        name = ''
        for item in line.split('|'):
            if item == 'DOMAIN':
                continue
            prop, val = item.split('=')
            if prop == 'name':
                name = val
                retdict[name] = {}
                continue
            if prop == 'state' and state != 'all':
                if val != state:
                    del retdict[name]
                    break
            if prop == 'flags' and guests_only:
                if 'c' in val or 'v' in val:
                    del retdict[name]
                    break
            retdict[name][prop] = val
    return retdict


def get_domain_constraints(domain=''):
    '''
    Get domain constraint data.

    :param str domain: Domain to get data on, if empty get data on all domains
    :rtype: dict
    :returns:
    Key: domain name
    Value: (structure example)
        uuid: 155e76bc-25dc-4fb7-a97b-fe7936bef8b6
        control:
          failure-policy: ignore
          extended-mapin-space: on
          cpu-arch: native
        variables:
          boot-device: /virtual-devices@100/channel-devices@200/disk@0:a net
          pm_boot_policy: disabled=0;ttfc=2000;ttmr=0;
        vnet:
          - name: pubnet0
            dev: network@1
            service: primary-vsw1
          - name: pubnet1
            dev: network@2
            service: secondary-vsw1
        vdisk: <-- same as vnet
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](LDM+' list-constraints -p '+domain,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying domain constraints',
                                    info=ret['stderr'])
    retdict = {}
    in_vars = False
    lines = ret['stdout'].splitlines()
    for index, line in enumerate(lines):
        if line.startswith('VERSION'):
            continue
        if line.startswith('DOMAIN'):
            domain = line.split('=')[1]
            retdict[domain] = {}
            continue
        if line.startswith('UUID'):
            retdict[domain]['uuid'] = line.split('=')[1]
            continue
        if line.startswith('VARIABLES'):
            in_vars = True
            continue
        if in_vars:
            if index+1 != len(lines):
                if not lines[index+1].startswith('|'):
                    in_vars = False
            if 'variables' not in retdict[domain]:
                retdict[domain]['variables'] = {}
            (tmp, _, val) = line.partition('=')
            retdict[domain]['variables'][tmp[1:]] = val
            continue
        if any([line.startswith('VNET'), line.startswith('VDISK')]):
            items = line.split('|')
            rdkey = items.pop(0).lower()
            if rdkey not in retdict[domain]:
                retdict[domain][rdkey] = []
            pdict = {}
            for item in items:
                (key, _, val) = item.partition('=')
                pdict[key] = val
            retdict[domain][rdkey].append(pdict)
            continue
        items = line.split('|')
        rdkey = items.pop(0).lower()
        if rdkey not in retdict[domain]:
            retdict[domain][rdkey] = {}
        for item in items:
            (key, _, val) = item.partition('=')
            retdict[domain][rdkey][key] = val
    return retdict


def get_chassis_cores():
    '''
    Get physical CPU core information for this chassis.

    :returns: Total and free cores. On error, 0 will be returned for both.
        Errors will be logged.
        Dict keys: total, free
    :rtype: dict
    '''
    logger = logging.getLogger(__name__)
    retdict = {'total': 0, 'free': 0}
    ret = __salt__['cmd.run_all']('{} list-devices -a -p core'.format(LDM))
    if ret['retcode'] != 0:
        logger.error('Error getting core data: %s', ret['stderr'])
        return retdict
    if not isinstance(ret['stdout'], str):
        logger.error('Expected str for stdout, got (%s)', ret['stdout'])
        return retdict
    for line in ret['stdout'].splitlines():
        if '|' not in line:
            continue
        retdict['total'] += 1
        if 'free=100' in line:
            retdict['free'] += 1
    return retdict


def get_chassis_ram():
    '''
    Get physical RAM information for this chassis.

    :returns: Total and free RAM (in GB). On error, 0 will be returned for both.
        Errors will be logged.
        Dict keys: total, free
    :rtype: dict
    '''
    logger = logging.getLogger(__name__)
    retdict = {'total': 0, 'free': 0}
    ret = __salt__['cmd.run_all']('{} list-devices -a -p mem'.format(LDM))
    if ret['retcode'] != 0:
        logger.error('Error getting RAM data: %s', ret['stderr'])
        return retdict
    if not isinstance(ret['stdout'], str):
        logger.error('Expected str for stdout, got (%s)', ret['stdout'])
        return retdict
    total_b = 0
    bound_b = 0
    for line in ret['stdout'].splitlines():
        if '|' not in line:
            continue
        items = line.split('|')
        size_item = items[2]
        size = int(size_item.split('=')[1])
        total_b += size
        if 'bound' in line:
            bound_b += size
    free_b = total_b - bound_b
    retdict['total'] = int((((total_b / 1024) / 1024) / 1024))
    retdict['free'] = int((((free_b / 1024) / 1024) / 1024))
    return retdict


def audit_vnets(domname):
    '''
    Check for lack of redundancy in the specified domain's vnets.
    This is broken out here because it is used in both the module function
    :py:func:`ldm.audit_guest` and the runner function
    :py:func:`sparc_ovm.fix_vnets`.

    :rtype: dict
    :returns:
        vnet_name1: pvid
    '''
    bad_vnets = {}
    vnets = __salt__['ldm.get_vnets'](domname)
    for vnet in vnets:
        vnet_name = vnet['name']
        vnet_pvid = vnet['pvid']
        if vnet_name == 'pubnet0':
            if not vnet['service'].startswith('primary-vsw1'):
                bad_vnets[vnet_name] = vnet_pvid
        elif vnet_name == 'pubnet1':
            if not vnet['service'].startswith('secondary-vsw1'):
                bad_vnets[vnet_name] = vnet_pvid
        elif vnet_name == 'privnet0':
            if not vnet['service'].startswith('primary-vsw2'):
                bad_vnets[vnet_name] = vnet_pvid
        elif vnet_name == 'privnet1':
            if not vnet['service'].startswith('secondary-vsw2'):
                bad_vnets[vnet_name] = vnet_pvid
        elif vnet_name == 'mgmt0':
            continue
    return bad_vnets


def audit_guest(domnames=None, verbose=False):
    '''
    Check for lack of redundancy and other possible issues on guest LDOMs.
    Primary and secondary domains are excluded.
    Inactive domains are also excluded because they must be bound in order to
    determine multipath status.

    :param str domnames: Single domain name or comma-separated list of domain
    names.  If None, all domains (except primary and secondary) will be audited.
    Default is None.
    :param bool verbose: Normally no output is given if no issues are found.
    If this is True, "no issues found" messages will be output.  Default is
    False.
    :rtype: dict
    :returns:
        LDOM name:
          vnets:
            vnet_name1: pvid      <-- non-redundant vnet and its pvid (VLAN)
            ...
          vdisks:                 <-- vdisks with only one vdsvol or wrong VDS#
            - vdisk_name1
            - vdisk_name2
            ...
          vcons: portnum          <-- hard-set virtual console port
          mpgroups:               <-- bad mpgroup names
            - mpgroup1
            - mpgroup2
              ...
    '''
    retdict = OrderedDict()
    log = logging.getLogger(__name__)
    all_vdsvols = get_vdsvols()
    guests = []
    if domnames is not None:
        domains = domnames.split(',')
        guests.extend(domains)
    else:
        try:
            domains = get_domains()
        except CommandExecutionError as err:
            return str(err)

        for name in domains:
            guests.append(name)
    if 'primary' in guests:
        guests.remove('primary')
    if 'secondary' in guests:
        guests.remove('secondary')
    skipped = []
    for guest in guests:
        try:
            state = domain_get_state(guest)
        except CommandExecutionError as err:
            if 'not found' in str(err):
                log.warning('Skipping nonexistent domain %s', guest)
                skipped.append(guest)
                continue
            raise

        if state == 'inactive':
            continue
        # vnet redundancy
        bad_vnets = audit_vnets(guest)
        if bad_vnets:
            retdict[guest] = {'vnets': bad_vnets}
        # vdisk redundancy
        # Get vdisks
        vdisks = get_vdisks(guest)
        # Get vdsvols
        if guest[-1:].isdigit():
            guest_ord = guest[-1:]
            vdsnum = str(int(guest_ord)-1)
        else:
            guest_ord = '1'
            vdsnum = '0'
        # Check pri/sec vds
        bad_vdisks = []
        bad_mpgroups = []
        for vdisk in vdisks:
            found_pri = False
            found_sec = False
            # If mpgroup names match, call it good
            for vdsvol in all_vdsvols['primary-vds'+vdsnum]:
                if vdsvol['mpgroup'] == vdisk['mpgroup']:
                    found_pri = True
                    break
            for vdsvol in all_vdsvols['secondary-vds'+vdsnum]:
                if vdsvol['mpgroup'] == vdisk['mpgroup']:
                    found_sec = True
                    break
            if not all([found_pri, found_sec]):
                bad_vdisks.append(vdisk['name'])
            # Skip OS disks
            if all(['DATA' not in vdisk['vol'], 'FRA' not in vdisk['vol'],
                    'OCR' not in vdisk['vol'], 'GIMR' not in vdisk['vol'],
                    not fnmatch.fnmatch('*[123456]-cmd*', vdisk['mpgroup'])]):
                continue
            if not vdisk['mpgroup'].endswith('_'+guest_ord):
                bad_mpgroups.append(vdisk['mpgroup'])
                if guest not in retdict:
                    retdict[guest] = {}
                retdict[guest]['mpgroups'] = bad_mpgroups
        if bad_vdisks:
            if guest not in retdict:
                retdict[guest] = {}
            retdict[guest]['vdisks'] = bad_vdisks
        # vcons port
        constraints = get_domain_constraints(guest)
        bad_vcons = ''
        if 'vcons' in constraints[guest]:
            bad_vcons = constraints[guest]['vcons']['port']
            if bad_vcons:
                if guest not in retdict:
                    retdict[guest] = {}
                retdict[guest]['vcons'] = bad_vcons
        if verbose:
            if guest not in retdict:
                retdict[guest] = {}
            if not bad_vnets:
                retdict[guest]['vnets'] = 'No issues found'
            if not bad_vdisks:
                retdict[guest]['vdisks'] = 'No issues found'
            if not bad_mpgroups:
                retdict[guest]['mpgroups'] = 'No issues found'
            if not bad_vcons:
                retdict[guest]['vcons'] = 'No issues found'
    if all([verbose, skipped]):
        retdict['nonexistent'] = '\n'.join(skipped)
    return retdict


def balance_vdisks(domnames=None):
    '''
    Set backend VDS volumes for all vdisks in the given domain(s) to alternate
    between primary and secondary service domains.
    This effectively "stripes" I/O across hardware HBAs.

    :param str domnames: Single domain name or comma-separated list of domain
    names.  If None, all domains (except primary and secondary) will be updated.
    Default is None.
    :returns: Changes made for each domain
    '''
    guests = []
    if domnames is not None:
        domains = domnames.split(',')
        guests.extend(domains)
    else:
        try:
            domains = get_domains()
        except CommandExecutionError as err:
            return str(err)

        for name in domains:
            guests.append(name)
    if 'primary' in guests:
        guests.remove('primary')
    if 'secondary' in guests:
        guests.remove('secondary')
    ret_lines = []
    for guest in guests:
        try:
            vdisks = get_vdisks(guest)
        except CommandExecutionError as err:
            return str(err)

        ret_lines.append('\n'+guest)
        ret_lines.append('==========================')
        svcdom = 'primary'
        for vdisk_dict in vdisks:
            vds = vdisk_dict['vol'].rpartition('-')[2]
            volname = vdisk_dict['vol'].split('@')[0]
            vol = volname+'@'+svcdom+'-'+vds
            cmd = LDM+' set-vdisk volume='+vol+' '+vdisk_dict['name']+' '+guest
            ret = __salt__['cmd.run_all'](cmd)
            if ret['retcode'] != 0:
                return ('Error setting vdisk volume '+vol+' on domain '+guest+
                        ':\n\n'+ret['stderr'])

            ret_lines.append('vdisk '+vdisk_dict['name']+' set to '+svcdom)
            if svcdom == 'primary':
                svcdom = 'secondary'
            else:
                svcdom = 'primary'
    return '\n'.join(ret_lines)


def audit_vdisks(domnames=None):
    '''
    Check vdisks for striping across service domains.  This includes both the
    configured path (as seen in ```ldm ls -o disk``` output), and the currently
    active path (as seen in ```ldm ls-bindings``` output).

    :param str domnames: Single domain name or comma-separated list of domain
    names.  If None, all domains (except primary and secondary) will be audited.
    Default is None.
    :returns: Two values for each domain: "configured" and "current".  Each
    value is boolean; if True, it is striped across service domains, if False
    it is not.
    '''
    guests = []
    if domnames is not None:
        domains = domnames.split(',')
        guests.extend(domains)
    else:
        try:
            domains = get_domains()
        except CommandExecutionError as err:
            return str(err)

        for name in domains:
            guests.append(name)
    if 'primary' in guests:
        guests.remove('primary')
    if 'secondary' in guests:
        guests.remove('secondary')
    ret_lines = []
    for guest in guests:
        # Configured
        try:
            vdisks = get_vdisks(guest)
        except CommandExecutionError as err:
            return str(err)

        ret_lines.append('\n'+guest)
        ret_lines.append('==========================')
        striped = True
        prev_svcdom = ''
        for vdisk_dict in vdisks:
            if vdisk_dict['server'] == prev_svcdom:
                striped = False
                break
            prev_svcdom = vdisk_dict['server']
        ret_lines.append('configured: '+str(striped))
        # Current
        cmd = LDM+' ls-bindings -p '+guest
        ret = __salt__['cmd.run_all'](cmd)
        if ret['retcode'] != 0:
            return 'Error getting bindings from '+guest+':\n\n'+ret['stderr']

        striped = True
        prev_svcdom = ''
        for line in ret['stdout'].splitlines():
            if 'mpg-path=active' not in line:
                continue
            item = line.split('|')[3]
            cur_svcdom = item.split('=')[1]
            if cur_svcdom == prev_svcdom:
                striped = False
                break
            prev_svcdom = cur_svcdom
        ret_lines.append('current: '+str(striped))
    return '\n'.join(ret_lines)
