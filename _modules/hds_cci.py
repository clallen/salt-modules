# -*- coding: utf-8 -*-
'''
Execution module for Hitachi CCI command-line tools

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

# Import python libs
# import logging
import re
import time
from collections import OrderedDict

# Import salt libs
from salt.exceptions import CommandExecutionError

# LOG = logging.getLogger(__name__)
RAIDCOM = '/HORCM/usr/bin/raidcom'
INQRAID = '/HORCM/usr/bin/inqraid'
PAIRCREATE = '/HORCM/usr/bin/paircreate'
PAIRDISPLAY = '/HORCM/usr/bin/pairdisplay'
PAIRSPLIT = '/HORCM/usr/bin/pairsplit'
LOCK_CMD = 'lock resource -resource_name meta_resource -time 60 -I'
UNLOCK_CMD = 'unlock resource -resource_name meta_resource -I'


def __virtual__():
    '''
    Verify that commands are available.
    '''
    if not __salt__['file.file_exists'](RAIDCOM):
        return False, 'Cannot find the executable '+RAIDCOM
    if not __salt__['file.file_exists'](INQRAID):
        return False, 'Cannot find the executable '+INQRAID
    if not __salt__['file.file_exists'](PAIRCREATE):
        return False, 'Cannot find the executable '+PAIRCREATE
    if not __salt__['file.file_exists'](PAIRDISPLAY):
        return False, 'Cannot find the executable '+PAIRDISPLAY
    if not __salt__['file.file_exists'](PAIRSPLIT):
        return False, 'Cannot find the executable '+PAIRSPLIT
    return True


class HORCMConf():
    '''
    HORCM config data.

    This consists primarily of device groups, represented by the following
    dict structure (self.groups):

    group_name1:
      devices:
        device_name1: LDEV_ID_1
        device_name2: LDEV_ID_2
        device_name3: LDEV_ID_3
        ...
      rhost: remote_host_name
      rinst: remote_instance_number
      mu: mirror_unit_number
    group_name2:
      ...
    group_name3:
      ...
    '''
    def __init__(self, inst, serial=None, init_from_file=False):
        '''
        :param str inst: HORCM instance number
        :param str serial: Frame decimal serial number, if None will be looked
        up in pillar
        :param bool init_from_file: If True, attempt to read group data from
        the config file for this instance.  Otherwise start with no data.
        :raises: IOError: if there are problems with the config file
        '''
        self.inst = str(inst)
        if serial is None:
            self.serial = __salt__['pillar.get']('san:frame_data:'+
                                                 self.inst+':serial_dec')
        else:
            self.serial = serial
        self.groups = OrderedDict()
        self.conf_file = '/etc/horcm'+self.inst+'.conf'
        if init_from_file:
            with open(self.conf_file, encoding='utf-8') as fd:
                conf_file_data = fd.read()
            in_ldev_block = False
            in_inst_block = False
            for line in conf_file_data.splitlines():
                if not line or line.startswith('#'):
                    continue
                # lines that have just whitespace, like tabs (argh)
                if re.match(r'^\s+$', line):
                    continue
                if line.startswith('HORCM_LDEV'):
                    in_ldev_block = True
                    continue
                if line.startswith('HORCM_INST'):
                    in_ldev_block = False
                    in_inst_block = True
                    continue
                if in_ldev_block:
                    cols = [col.lower() for col in line.split()]
                    if cols[0] not in self.groups:
                        self.groups[cols[0]] = {'devices': OrderedDict()}
                    self.groups[cols[0]]['devices'][cols[1]] = cols[3]
                    if 'mu' not in self.groups[cols[0]]:
                        self.groups[cols[0]]['mu'] = cols[4]
                    continue
                if in_inst_block:
                    cols = [col.lower() for col in line.split()]
                    self.groups[cols[0]]['rhost'] = cols[1]
                    self.groups[cols[0]]['rinst'] = cols[2][-1:]

    def add_group(self, name, devices, rhost, rinst, mirr_unit,
                  exclude=None):
        '''
        Add a device group to the config data.

        :param str name: Group name
        :param dict devices: Same structure as output of
        :py:func:`find_ldev_ids`
        :param str rhost: Remote host
        :param str rinst: Remote HORCM instance number
        :param str mirr_unit: Mirror unit
        :param str exclude: LDEV names containing this string will be excluded
        '''
        name_to_id = OrderedDict()
        for ldev_name, ldict in devices.items():
            if exclude is not None:
                if exclude in ldev_name:
                    continue
            name_to_id[ldev_name] = ldict['id']
        self.groups[name] = {'devices': name_to_id}
        self.groups[name]['mu'] = mirr_unit
        self.groups[name]['rhost'] = rhost
        self.groups[name]['rinst'] = rinst

    def ldev_in_group(self, ldev_id):
        '''
        Get the device group which contains the specified LDEV ID.

        :param str ldev_id: LDEV ID
        :rtype: str
        :returns: The group name, or an empty string if not found
        '''
        name = ''
        for group in self.groups:
            for ldev in self.groups[group]['devices'].values():
                if ldev == ldev_id:
                    name = group
        return name

    def config_exists(self):
        '''
        Check for the existence of the HORCM config file.

        :rtype: bool
        '''
        return __salt__['file.file_exists'](self.conf_file)

    def config_write(self, host):
        '''
        Write the config file for this instance.  If one already exists it will
        be overwritten.

        :param str host: Hostname for this instance (used in the HORCM_MON
        section)
        '''
        # pylint: disable=un-indexed-curly-braces-error
        ldev_colfmt = '{:30}{:30}{:10}{:18}{}'
        inst_colfmt = '{:30}{:15}{}'
        ldev_lines = []
        inst_lines = []
        for group, gdict in self.groups.items():
            for dev_name in gdict['devices']:
                ldev_line = ldev_colfmt.format(group.lower(), dev_name,
                                               self.serial,
                                               gdict['devices'][dev_name],
                                               gdict['mu'])
                ldev_lines.append(ldev_line)
            inst_line = inst_colfmt.format(group.lower(), gdict['rhost'],
                                           'horcm'+gdict['rinst'])
            inst_lines.append(inst_line)
        conf_template = ('HORCM_MON\n{:15}{:10}{:15}{}\n{:15}{:10}{:15}{}'
                         '\n\nHORCM_CMD\n#dev name\n\\\\.\\CMD-{}:/dev/rdsk/*\n'
                         '\nHORCM_LDEV\n'+ldev_colfmt+'\n'
                         '{}\n\nHORCM_INST\n'+inst_colfmt+'\n{}\n')
        output = conf_template.format('#ip_address', 'service', 'poll(10ms)',
                                      'timeout(10ms)', host,
                                      'horcm'+self.inst, '1000', '3000',
                                      self.serial, '#dev_group', 'dev_name',
                                      'Serial#', 'CU:LDEV(LDEV#)', 'MU#',
                                      '\n'.join(ldev_lines), '#dev_group',
                                      'ip_address', 'service',
                                      '\n'.join(inst_lines))
        __salt__['file.write'](self.conf_file, output)


class HORCMInst(HORCMConf):
    '''
    HORCM instance operations.
    '''
    def __init__(self, inst):
        '''
        :param str inst: HORCM instance number
        '''
        super().__init__(inst)

    def copy_group(self, group):
        '''
        Start the ShadowImage process on the specified group.

        :param str group: Group to copy
        :raises: CommandExecutionError: Problem running a shell command
        '''
        cmd = PAIRCREATE+' -g '+group+' -split -pvol -ISI'+self.inst
        ret = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError(ret['stderr'], info=cmd)

    def split_group(self, group, force=False):
        '''
        Stop the ShadowImage process on the specified group.

        :param str group: Group to split
        :param bool force: Split group even if a copy is in progress
        :raises: CommandExecutionError: Problem running a shell command
        '''
        if force:
            cmd = PAIRSPLIT+' -g '+group+' -E -ISI'+self.inst
            ret = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
            if ret['retcode'] != 0:
                raise CommandExecutionError(ret['stderr'], info=cmd)
        cmd = PAIRSPLIT+' -g '+group+' -S -ISI'+self.inst
        ret = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError(ret['stderr'], info=cmd)

    def group_status(self, group):
        '''
        :param str group: Group to check
        :rtype: str
        :returns: One of:
        * copy: copying
        * smpl: not copying
        * sync: copy is idle, can be split
        * none: group does not exist
        :raises: CommandExecutionError: Problem running a shell command
        '''
        cmd = PAIRDISPLAY+' -g '+group+' -ISI'+self.inst
        ret = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
        if ret['retcode'] == 251:  # unable to connect to HORCM
            return 'smpl'
        if ret['retcode'] != 0:
            if 'No such device or group' in ret['stderr']:
                return 'none'
            raise CommandExecutionError(ret['stderr'], info=cmd)

        if 'COPY' in ret['stdout']:
            return 'copy'

        if 'SMPL' in ret['stdout']:
            return 'smpl'

        return 'sync'

    def svcinst_exists(self):
        '''
        Check for the SMF service instance.

        :rtype: bool
        :raises: CommandExecutionError: Problem running a shell command
        '''
        horcm_name = 'horcm'+self.inst
        cmd = '/usr/sbin/svccfg -s site/horcm:'+horcm_name+' list'
        cmd_out = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
        if ':properties' in cmd_out['stdout']:
            ret = True
        elif 'doesn\'t match' in cmd_out['stderr']:
            ret = False
        elif cmd_out['retcode']:
            raise CommandExecutionError('Checking HORCM svc instance failed',
                                        info=cmd_out['stderr'])

        return ret

    def setup_svcinst(self):
        '''
        Setup the SMF service instance.

        :raises: CommandExecutionError: Problem running a shell command
        '''
        horcm_name = 'horcm'+self.inst
        for cmd in ['/usr/sbin/svccfg -s site/horcm add '+horcm_name,
                    ('/usr/sbin/svccfg -s site/horcm:'+horcm_name+
                     ' addpg general framework'),
                    ('/usr/sbin/svccfg -s site/horcm:'+horcm_name+
                     ' addpropvalue '+'general/enabled boolean: false')]:
            ret = __salt__['cmd.run_all'](cmd)
            if ret['retcode'] != 0:
                raise CommandExecutionError(ret['stderr'], info=cmd)

    def start(self, timeout=60):
        '''
        Start this instance.

        :param int timeout: Time in seconds to wait for instance to start
        :raises: CommandExecutionError: Instance failed to start
        '''
        if __salt__['ps.pgrep']('horcmd_0'+self.inst, full=True) is None:
            __salt__['service.start']('horcm'+self.inst)
            count = 1
            while __salt__['ps.pgrep']('horcmd_0'+self.inst, full=True) is None:
                time.sleep(1)
                if count == timeout:
                    __salt__['service.disable']('horcm'+self.inst)
                    raise CommandExecutionError('HORCM instance '+self.inst+
                                                ' failed to start')

                count += 1

    def stop(self):
        '''
        Stop this instance.
        '''
        __salt__['service.stop']('horcm'+self.inst)
        time.sleep(5)

    def is_running(self):
        '''
        Get running status of this instance.
        :rtype: bool
        '''
        if __salt__['ps.pgrep']('horcmd_0'+self.inst, full=True) is None:
            return False
        return True


class LDEV():
    '''
    Data describing an LDEV storage unit, along with methods to create,
    delete, share, and unshare.

    Properties:
    * frame: SAN frame number
    * id_str: LDEV ID (hex XX:XX)
    * name: LDEV label (empty string if no label set)
    * capacity: Capacity in GB (will be 0 if LDEV is not defined)
    * sharing: Sharing data, with structure:
      ```
      ldev_id:
        port:
          - host
      ```
    '''
    def __init__(self, frame, id_str):
        '''
        :raises: ValueError: invalid input
        :raises: CommandExecutionError: problem running a shell command
        '''
        self.frame = str(frame)
        self.id_str = str(id_str)
        if self.frame not in __salt__['pillar.get']('san:frame_data'):
            raise ValueError('Invalid frame: '+self.frame)
        if re.match(r'^[a-f0-9]{2}:[a-f0-9]{2}$', self.id_str, re.I) is None:
            raise ValueError('Invalid LDEV ID: '+self.id_str)
        self.name = ''
        self.capacity = None
        # Sharing dict - {port: [hosts]}
        self.sharing = {}
        # Get raidcom data
        cmd = RAIDCOM+' get ldev -ldev_id '+self.id_str+' -I'+self.frame
        cmd_out = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
        if cmd_out['retcode'] != 0:
            raise CommandExecutionError(cmd_out['stderr'], info=cmd)
        # Populate object data, if LDEV exists
        if 'NOT DEFINED' not in cmd_out['stdout']:
            for line in cmd_out['stdout'].splitlines():
                if line.startswith('LDEV_NAMING'):
                    items = line.split(' : ')
                    self.name = items[1]
                elif line.startswith('VOL_Capacity'):
                    items = line.split(' : ')
                    if len(items) == 2:
                        self.capacity = ((int(items[1])/2)/1024)/1024
                elif line.startswith('PORTs'):
                    port_items = line.split(' : ')
                    port_items.pop(0)
                    for port_item in port_items:
                        port = port_item.split()[0].rpartition('-')[0].lower()
                        host = port_item.split()[2]
                        if port not in self.sharing:
                            self.sharing[port] = [host]
                        elif host not in self.sharing[port]:
                            self.sharing[port].append(host)

    def create(self, size, in_mb=False):
        '''
        :param str size: Capacity in GB
        :param bool in_mb: If True, the size argument is used as MB
        :rtype: str
        :returns: "success" or "exists"
        :raises: LookupError: Unable to find the pool for an LDEV CU
        :raises: CommandExecutionError: Problem running a shell command
        '''
        exists_str = 'LDEV is already defined'
        ret = 'success'
        # set capacity suffix
        if in_mb:
            cap_sfx = 'm'
        else:
            cap_sfx = 'g'
        # lookup pool
        pools = __salt__['pillar.get']('san:frame_data:'+self.frame+':pools')
        pool = 0
        ldev_cu = self.id_str[0:2].upper()
        for pool_id, cu_list in pools.items():
            if ldev_cu in cu_list:
                pool = pool_id
                break
        if pool == 0:
            raise LookupError('Unable to find pool for CU '+ldev_cu)

        # create ldev
        cmd = (RAIDCOM+' add ldev -pool '+pool+' -ldev_id '+self.id_str+
               ' -capacity '+size+cap_sfx+' -I'+self.frame)
        cmd_out = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
        if cmd_out['retcode'] != 0:
            if exists_str in cmd_out['stderr']:
                ret = 'exists'
            else:
                raise CommandExecutionError(cmd_out['stderr'], info=cmd)

        # update instance data
        if self.capacity is None:
            self.capacity = size
        return ret

    def set_name(self, name):
        '''
        :param str name: Each LDEV will have this name, appended with a
        sequential index (i.e. NAME_01, NAME_02, etc.).
        Must be alphanumeric, can contain underscores and hyphens.
        :raises: ValueError: Invalid name argument
        :raises: CommandExecutionError: Problem running a shell command
        '''
        # validate name
        if re.match(r'^[\w-]+$', name) is None:
            raise ValueError('Invalid "name" argument: "'+name+'".  Must be '
                             'alphanumeric, can contain underscores and '
                             'hyphens')

        # set ldev name
        cmd = (RAIDCOM+' modify ldev -ldev_id '+self.id_str+' -ldev_name '+
               name+' -I'+self.frame)
        cmd_out = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
        if cmd_out['retcode'] != 0:
            raise CommandExecutionError(cmd_out['stderr'], info=cmd)

        # update instance data
        if not self.name:
            self.name = name

    def delete(self):
        '''
        :rtype: str
        :returns: "success" on success.
        Otherwise one of: "does not exist" or "shared".
        :raises: CommandExecutionError: Problem running a shell command
        '''
        not_exists_str = 'LDEV is not installed'
        path_defined_str = 'A path is defined in the volume'
        ret = 'success'
        # delete
        cmd = RAIDCOM+' delete ldev -ldev_id '+self.id_str+' -I'+self.frame
        cmd_out = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
        if cmd_out['retcode'] != 0:
            if not_exists_str in cmd_out['stderr']:
                ret = 'does not exist'
            elif path_defined_str in cmd_out['stderr']:
                ret = 'shared'
            else:
                raise CommandExecutionError(cmd_out['stderr'], info=cmd)

        # update instance data
        self.name = ''
        self.capacity = None
        return ret

    def share(self, ports, hosts):
        '''
        :param list ports: Ports to share on
        :param list hosts: Hosts to share to
        :rtype: dict
        :returns: Results of sharing attempts in two nested dicts:
        ```
        'shared':
          port:
            - host
        'existing':
          port:
            - host
        ```
        The "existing" dict will contain ports/hosts that are already shared to,
        or will be empty if none are already shared.
        If the LDEV does not exist an empty dict will be returned.
        :raises: ValueError: Invalid port format
        :raises: CommandExecutionError: Problem running a shell command
        '''
        shared_str = 'An LU path has already defined'
        # validate ports
        for port in ports:
            if re.match(r"CL\d{1}-[a-z]{1}", port, re.I) is None:
                raise ValueError('Invalid port format: '+port)

        # return empty on nonexistent LDEV
        if self.capacity is None:
            return {}

        ret = {'shared': {}, 'existing': {}}
        # share ldevs
        for port in ports:
            for host in hosts:
                cmd = (RAIDCOM+' add lun -port '+port+' '+host+
                       ' -ldev_id '+self.id_str+' -I'+self.frame)
                cmd_out = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
                if cmd_out['retcode'] == 0:
                    if port not in ret['shared']:
                        ret['shared'][port] = [host]
                    elif host not in ret['shared'][port]:
                        ret['shared'][port].append(host)
                elif shared_str in cmd_out['stderr']:
                    if port not in ret['existing']:
                        ret['existing'][port] = [host]
                    elif host not in ret['existing'][port]:
                        ret['existing'][port].append(host)
                else:
                    raise CommandExecutionError(cmd_out['stderr'], info=cmd)

        # update instance data
        if not self.sharing:
            self.sharing.update(ret['shared'])
        else:
            for port, ret_hosts in ret['shared'].items():
                if port in self.sharing:
                    new_hosts = set(self.sharing[port])
                    new_hosts.update(set(ret_hosts))
                    self.sharing[port] = list(new_hosts)
                else:
                    self.sharing[port] = ret_hosts
        return ret

    def unshare(self, ports=None, hosts=None):
        '''
        :param list ports: Ports to unshare on, if None all shared ports are
        used
        :param list hosts: Hosts to unshare from, if None unshare from all hosts
        :rtype: dict
        :returns: Results of unsharing attempts in two nested dicts:
        ```
        'unshared':
          port:
            - host
        'existing':
          port:
            - host
        ```
        The "existing" dict will contain ports/hosts that are already unshared,
        or will be empty if none are already unshared.
        If the LDEV is not shared, an empty dict will be returned.
        :raises: CommandExecutionError: Problem running a shell command
        '''
        not_shared_str = 'could not find an LUN for deleting'
        no_such_obj_str = 'No such Object in the RAID'
        ret = {'unshared': {}, 'existing': {}}
        # find data if not given in args
        if ports is None:
            ports = list(self.sharing.keys())
        if hosts is None:
            hosts = set()
            for hlist in self.sharing.values():
                hosts.update(hlist)
        # return empty on unshared LDEV
        if any([not ports, not hosts]):
            return {}

        # unshare ldevs
        for port in ports:
            if re.match(r"CL\d{1}-[a-z]{1}", port, re.I) is None:
                raise ValueError('Invalid port format: '+port)

            for host in hosts:
                cmd = (RAIDCOM+' delete lun -port '+port+' '+host+
                       ' -ldev_id '+self.id_str+' -I'+self.frame)
                cmd_out = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
                if cmd_out['retcode'] == 0:
                    if port not in ret['unshared']:
                        ret['unshared'][port] = [host]
                    elif host not in ret['unshared'][port]:
                        ret['unshared'][port].append(host)
                elif any([not_shared_str in cmd_out['stderr'],
                          no_such_obj_str in cmd_out['stderr']]):
                    if port not in ret['existing']:
                        ret['existing'][port] = [host]
                    elif host not in ret['existing'][port]:
                        ret['existing'][port].append(host)
                else:
                    raise CommandExecutionError(cmd_out['stderr'], info=cmd)

        # update instance data
        if self.sharing:
            for port, ret_hosts in ret['unshared'].items():
                if port in self.sharing:
                    new_hosts = set(self.sharing[port])
                    new_hosts.difference_update(set(ret_hosts))
                    if new_hosts:
                        self.sharing[port] = list(new_hosts)
                    else:
                        del self.sharing[port]
        return ret


def horcmconf_exists(inst):
    '''
    Check if the config file for the given HORCM instance exists.

    :param str inst: HORCM instance number
    :rtype: bool
    '''
    sinst = str(inst)
    return HORCMConf(sinst).config_exists()


def horcmconf_write(inst, hostname, data=None):
    '''
    Write the config file for the given HORCM instance.

    :param str inst: HORCM instance number
    :param str hostname: Hostname for this instance (used in the HORCM_MON
    section)
    :param list data: Dicts describing config data.  See arguments for
    :py:class:`HORCMConf.add_group` for keys/values.
    May be omitted to generate a "bare" config (just enough to allow the HORCM
    instance to start).
    '''
    sinst = str(inst)
    horcmconf = HORCMConf(sinst)
    if data is not None:
        for group in data:
            horcmconf.add_group(group['name'],
                                group['devices'],
                                group['rhost'],
                                group['rinst'],
                                group.get('mirr_unit', '0'),
                                exclude=group.get('exclude'))
    horcmconf.config_write(hostname)


def horcminst_exists(inst):
    '''
    Check if the given HORCM SMF service instance is configured.

    :param str inst: HORCM instance number
    :rtype: bool
    '''
    sinst = str(inst)
    return HORCMInst(sinst).svcinst_exists()


def setup_horcminst(inst):
    '''
    Configure the given HORCM SMF service instance.

    :param str inst: HORCM instance number
    :raises: CommandExecutionError: Problem running a shell command
    '''
    sinst = str(inst)
    HORCMInst(sinst).setup_svcinst()


def get_horcm_groups(inst):
    '''
    Get HORCM group data for the given instance.

    :param str inst: HORCM instance number
    :rtype: OrderedDict
    :returns: Key: group name, Value: group data.  If the config file for the
    given instance was not found or could not be read, returns an empty dict
    '''
    sinst = str(inst)
    try:
        horcm_conf = HORCMConf(sinst, init_from_file=True)
    except IOError:
        return {}
    else:
        return horcm_conf.groups


def create_ldevs(inst, name, ldev_ids, capacity, in_mb=False, name_index=1):
    '''
    Create the specified LDEVs.

    :param str inst: HORCM instance number
    :param str name: Each LDEV will have this name, appended with a sequential
    index (i.e. NAME_01, NAME_02, etc.).
    Must be alphanumeric, can contain underscores and hyphens.
    :param list ldev_ids: LDEV IDs
    :param str capacity: Capacity of each LDEV in GB
    :param bool in_mb: If True, the capacity argument is used as MB
    :param int name_index: Number at which sequential indexes start.  Can be
    None to disable indexing, but should only be done for single LDEVs.
    :rtype: dict
    :returns: Keys: LDEV IDs
    Values: 'success' or 'exists'
    :raises: LookupError: Unable to find the pool for an LDEV CU
    :raises: ValueError: Invalid input data
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = {}
    sinst = str(inst)
    if all([name_index is None, len(ldev_ids) > 1]):
        raise ValueError('name_index cannot be None with multiple LDEVs')

    name_idx = name_index
    for ldev_id in ldev_ids:
        # Create
        ldev = LDEV(sinst, ldev_id)
        ret[ldev_id] = ldev.create(capacity, in_mb)
        # Name
        if name_idx is not None:
            if name_idx > 9:
                display_name = name+'_'+str(name_idx)
            else:
                display_name = name+'_0'+str(name_idx)
            name_idx += 1
        else:
            display_name = name
        # Insert delay to allow raidcom to catch up
        time.sleep(1)
        ldev.set_name(display_name)
    return ret


def delete_ldevs(inst, ldev_ids):
    '''
    Delete the specified LDEVs.

    :param str inst: HORCM instance number
    :param list ldevs: LDEV IDs
    :rtype: dict
    :returns: Keys: LDEVs IDs
    Values: 'success', 'does not exist', or 'shared'
    :raises: ValueError: Invalid input data
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = {}
    sinst = str(inst)
    for ldev_id in ldev_ids:
        ldev = LDEV(sinst, ldev_id)
        ret[ldev_id] = ldev.delete()
    return ret


def share_ldevs(inst, ldev_ids, ports, hosts):
    '''
    Share LDEVs to specified hosts on specified ports.

    :param str inst: HORCM instance number
    :param list ldev_ids: LDEV ID strings
    :param list ports: SAN ports
    :param list hosts: Hostnames
    :rtype: dict
    :returns: Results of sharing attempts (per LDEV) in two nested dicts:
    ```
    ldev_id:
      'shared':
        port:
          - host
      'existing':
        port:
          - host
    ```
    The "existing" dict will contain ports/hosts that are already shared to,
    or will be empty if none are already shared.
    If the LDEV does not exist an empty dict will be returned.
    :raises: ValueError: Invalid input data
    :raises: CommandExecutionError: Problem running shell commands
    '''
    ret = {}
    sinst = str(inst)
    for ldev_id in ldev_ids:
        ldev = LDEV(sinst, ldev_id)
        shared = ldev.share(ports, hosts)
        ret[ldev_id] = shared
    return ret


def unshare_ldevs(inst, ldev_ids, ports=None, hosts=None):
    '''
    Unshare LDEVs, optionally from specified hosts on specified ports.

    :param str inst: HORCM instance number
    :param list ldev_ids: LDEV IDs
    :param list ports: Ports to unshare on, if None unshare on all ports the
    LDEVs are shared on
    :param list hosts: Hosts to unshare from, if None unshare from all hosts the
    LDEVs are shared to
    :rtype: dict
    :returns: Results of unsharing attempts (per LDEV) in two nested dicts:
    ```
    ldev_id:
      'unshared':
        port:
          - host
      'existing':
        port:
          - host
    ```
    The "existing" dict will contain ports/hosts that are already unshared,
    or will be empty if none are already unshared.
    If the LDEV does not exist or is not shared, an empty dict will be returned.
    :raises: ValueError: Invalid input data
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = {}
    sinst = str(inst)
    for ldev_id in ldev_ids:
        ldev = LDEV(sinst, ldev_id)
        unshared = ldev.unshare(ports, hosts)
        ret[ldev_id] = unshared
    return ret


def get_ldevs_metadata(inst, ldev_ids):
    '''
    Get meta and sharing data for the specified LDEV IDs.

    :param str inst: HORCM instance number
    :param list ldev_ids: LDEV IDs to query
    :rtype: dict
    :returns: Structure:
    ```
    ldev_id:
      'name': name
      'capacity': capacity in GB
      'sharing':
        port:
          - host
    ```
    If an LDEV is not shared, the "sharing" dict will be empty.
    If an LDEV does not exist (i.e. has no capacity defined), its subdict will
    be empty.
    :raises: ValueError: Invalid input data
    :raises: CommandExecutionError: Problem running shell commands
    '''
    ret = {}
    sinst = str(inst)
    for ldev_id in ldev_ids:
        ldev = LDEV(sinst, ldev_id)
        # return empty subdict for undefined LDEVs
        if ldev.capacity is None:
            ret[ldev_id] = {}
            continue
        ret[ldev_id] = {'name': ldev.name}
        ret[ldev_id]['capacity'] = ldev.capacity
        ret[ldev_id]['sharing'] = ldev.sharing
    return ret


def hds_scan():
    '''
    Use the "inqraid" command to get storage currently shared to this system.

    :rtype: list
    :returns: Dicts with structure:
        device: c0t60060E8007C3C0000030C3C00000170Ad0s2
        port: CL2-C
        serial_dec: 350112
        id: 15:6C
        label: T1EBIZ_DATA_14
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all']('ls /dev/rdsk/* | '+INQRAID+' -fnx -CLI',
                                  python_shell=True, output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error scanning for LDEV IDs',
                                    info=ret['stderr'])
    results = []
    for line in ret['stdout'].splitlines():
        columns = line.split()
        if not columns[2].isdigit():
            continue
        rdict = {}
        rdict['device'] = columns[0]
        rdict['port'] = columns[1]
        rdict['serial_dec'] = columns[2]
        _ = columns[3]
        if len(_) == 3:
            ldev_id = '0'+_[:1]+':'+_[1:]
        else:
            ldev_id = _[:2]+':'+_[2:]
        rdict['id'] = ldev_id
        rdict['label'] = columns[8]
        results.append(rdict)
    return results


def find_ldev_ids(name):
    '''
    Search storage shared to this system and get LDEV IDs (and related data)
    which match LDEV labels.

    :param str name: The LDEV name to search.  Matching will be done on the
    string preceding the last underscore ("_").
    Examples:
      "19C_PROD_DATA" will match
        * 19C_PROD_DATA_01
        * 19C_PROD_DATA_02
        * 19C_PROD_DATA_03
      "19C_PROD_DATA2" will match
        * 19C_PROD_DATA2_01
        * 19C_PROD_DATA2_02
        * 19C_PROD_DATA2_03
    :rtype: OrderedDict
    :returns:
        LDEVNAME1:
          id: 15:6C
          inst: 6
        LDEVNAME2:
          id: 15:6D
          inst: 6
    Empty if no matches found.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = hds_scan()
    retdict = OrderedDict()
    frame_data = __salt__['pillar.get']('san:frame_data')
    for ldict in ret:
        label = ldict['label']
        base_name = label.rpartition('_')[0]
        if base_name != name:
            continue
        ldev_id = ldict['id']
        for pinst, pdict in frame_data.items():
            if pdict['serial_dec'] == ldict['serial_dec']:
                retdict[label] = {'id': ldev_id, 'inst': pinst}
                break
    return retdict


def get_hostgroups(inst, port):
    '''
    Get host group names associated with the given HORCM instance and port.

    :param str inst: HORCM instance number
    :param str port: Port to lookup (format is "cl5-g")
    :rtype: list
    :raises: CommandExecutionError: Problem running a shell command
    '''
    sinst = str(inst)
    cmd = RAIDCOM+' get host_grp -port '+port+' -I'+str(sinst)
    ret = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
    if ret['retcode'] == 251:
        raise CommandExecutionError('Cannot attach to HORCM instance')
    if ret['retcode'] == 253:
        raise CommandExecutionError('Invalid argument to raidcom command')
    if ret['retcode'] != 0:
        raise CommandExecutionError(ret['stderr'], info=cmd)
    groups = []
    for line in ret['stdout'].splitlines():
        if line.startswith('PORT'):
            continue
        cols = line.split()
        if len(cols) != 5:
            continue
        groups.append(cols[2])
    return groups


def add_hostgroup(inst, port, host, wwns):
    '''
    Add a host group on the specified port, for the specified host, using the
    specified WWNs.  The host group name will be the same as the hostname.

    WWN nicknames will be set as the hostname with a 1-indexed counter appended.
    Example: given a hostname of "selma-pri", nicknames would be "selma-pri-1"
    for the first WWN, "selma-pri-2" for the second, etc.

    :param str inst: HORCM instance number
    :param str port: The SAN port
    :param str host: The hostname
    :param list wwns: WWNs on the host
    :raises: CommandExecutionError: Problem running a shell command
    '''
    sinst = str(inst)
    # Create host group
    cmd = RAIDCOM+' add host_grp -port '+port+' -host_grp_name '+host+' -I'+sinst
    ret = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError(ret['stderr'], info=cmd)
    # Add WWNs
    for idx, wwn in enumerate(wwns, 1):
        for cmd in [(RAIDCOM+' add hba_wwn -port '+port+' '+host+' -hba_wwn '+
                     wwn+' -I'+sinst),
                    (RAIDCOM+' set hba_wwn -port '+port+' '+host+' -hba_wwn '+
                     wwn+' -wwn_nickname '+host+'-'+str(idx)+' -I'+sinst)]:
            ret = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
            if ret['retcode'] != 0:
                raise CommandExecutionError(ret['stderr'], info=cmd)


def enum_ldevs(begin, end):
    '''
    Generate a sequential list of LDEVs.

    :param str begin: Beginning LDEV ID
    :param str end: Ending LDEV ID
    :rtype: list
    :returns: Hex LDEV IDs from begin to end, inclusive
    '''
    ldev_cu = begin[0:2].upper()
    dec_begin_idx = int(begin[3:5], 16)
    dec_end_idx = int(end[3:5], 16)
    ret = []
    for dec_idx in range(dec_begin_idx, dec_end_idx+1):
        hex_idx = format(dec_idx, 'X')
        if len(hex_idx) < 2:
            hex_idx = '0'+hex_idx
        ret.append(ldev_cu+':'+hex_idx)
    return ret


def enable_cmddev(inst, ldev_id):
    '''
    Make the specified LDEV into an unauthenticated command device.
    It must have a capacity of 48MB.

    :param str inst: HORCM instance number
    :param str ldev_id: LDEV to modify
    :raises: CommandExecutionError: Problem running a shell command
    '''
    sinst = str(inst)
    cmd = ' modify ldev -ldev_id '+ldev_id+' -command_device y 0 -I'+sinst
    ret = __salt__['cmd.run_all'](RAIDCOM+cmd, output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError(ret['stderr'], info=cmd)


def rename_ldev(inst, ldev_id, name):
    '''
    Relabel an LDEV.

    :param str inst: HORCM instance number
    :param str ldev_id: LDEV to rename
    :param str name: Name to set
    :raises: CommandExecutionError: Problem running a shell command
    '''
    sinst = str(inst)
    ldev = LDEV(sinst, ldev_id)
    ldev.set_name(name.upper())
