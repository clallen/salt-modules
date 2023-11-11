# -*- coding: utf-8 -*-
'''
Execution module for gathering system data to populate the systems database

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

import logging
import time
from salt.exceptions import CommandExecutionError


class BadResponseError(Exception):
    '''
    Raised when data from a remote system is invalid in some way, usually
    wrong type.
    '''


class prtDiag():
    '''
    Class that interfaces to the 'prtdiag' command.
    '''
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.entries = {}
        self.prtdiag = '/sbin/prtdiag'
        self._get_prtdiag()

    def _get_prtdiag(self):
        self.logger.info("Retreiving 'prtdiag' data ...")
        stdout = __salt__['cmd.run_stdout'](self.prtdiag, success_retcodes=[1])
        found_on_line = False
        for line in stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
            if not found_on_line and 'on-line' in line:
                found_on_line = True
                (_, clock, factor, cpu_type, _) = line.split(None, 4)
                self.entries['cpu'] = ':'.join((clock, factor, cpu_type))
            else:
                continue

    def __getitem__(self, key):
        return self.entries[key]


class MpStat():
    '''
    Class that interfaces with the 'mpstat' command.
    '''
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.entries = {}
        self.mpstat = '/bin/mpstat'
        self._get_mpstat()

    def _get_mpstat(self):
        self.logger.info("Retreiving 'mpstat' data ...")
        stdout = __salt__['cmd.run_stdout'](self.mpstat)
        for line in stdout.split('\n'):
            line = line.strip()
            if not line or 'CPU' in line:
                continue
            idx, nada = line.split(None, 1)
            self.entries[idx] = nada

    def __len__(self):
        return len(self.entries)


class IPMITool():
    '''
    Class that interfaces with the 'ipmitool' command.
    '''
    #
    # Typical 'ipmitool fru' output from T'Series:
    #
    # FRU Device Description : Builtin FRU Device (LUN 0 ID 0)
    #  Product Manufacturer  : Oracle Corporation
    #  Product Name          : ILOM
    #  Product Version       : 4.0.3.1
    #
    # FRU Device Description : BMC
    #  Product Manufacturer  : Oracle Corporation
    #  Product Name          : ILOM
    #  Product Version       : 4.0.3.1
    #
    # FRU Device Description : /SYS (LUN 0 ID 3)
    #  Chassis Type          : Rack Mount Chassis
    #  Product Manufacturer  : Oracle Corporation
    #  Product Name          : SPARC T7-2
    #  Product Part Number   : 34460534+1+1
    #  Product Serial        : AK00375544
    #
    # FRU Device Description : DBP (LUN 0 ID 210)
    #  Board Mfg Date        : Thu May 12 22:09:00 2016
    #  Board Mfg             : Oracle Corporation
    #  Board Product         : PCA,NVME,6DBP,G3N
    #  Board Serial          : 464507N+1615M700EU
    #  Board Part Number     : 7096096
    #  Board Extra           : Rev 05
    #
    # FRU Device Description : PCIE1/PCIESW (LUN 0 ID 126)
    #  Device not present (Requested sensor, data, or record not found)
    #
    # FRU Device Description : PCIE2/PCIESW (LUN 0 ID 127)
    #  Device not present (Requested sensor, data, or record not found)
    #
    # FRU Device Description : MB/SPM (LUN 0 ID 1)
    #  Board Mfg Date        : Wed Jul  6 00:27:00 2016
    #  Board Mfg             : Oracle Corporation
    #  Board Product         : ASY,SP,T7/M7,8Gbit
    #
    #  Board Serial          : 465769T+1627NM0G8C
    #  Board Part Number     : 7319380
    #  Board Extra           : Rev 01
    #
    # Notes:
    #
    #  Not all entries have a ':' - see 'Device not present ...' entries above
    #
    #  There may be a line break within 'FRU Device Description' block. See the
    #  'MB/SPM (LUN 0 ID 1)' entry above.

    #
    # Typical output from 'ipmitool sunoem cli "show /System"':
    #
    # Connected. Use ^D to exit.
    # mrburns-rsc-> show /System
    #
    #  /System
    #     Targets:
    #         Open_Problems (0)
    #         Processors
    #         Memory
    #         Power
    #         Cooling
    #         Storage
    #         Networking
    #         PCI_Devices
    #         Firmware
    #         Log
    #
    #     Properties:
    #         health = OK
    #         health_details = -
    #         open_problems_count = 0
    #         type = Rack Mount
    #         model = SPARC T7-2
    #         qpart_id = Q10833
    #         part_number = 34460534+1+1
    #         serial_number = AK00375544
    #         system_identifier = (none)
    #         system_fw_version = Sun System Firmware 9.8.6 2018/06/13 09:41
    #         primary_operating_system = Oracle Solaris 11.3 SPARC
    #         primary_operating_system_detail = -
    #         host_primary_mac_address = 00:10:e0:bb:9b:04
    #         ilom_address = 130.164.47.191
    #         ilom_mac_address = 00:10:E0:BB:9B:0D
    #         locator_indicator = Off
    #         power_state = On
    #         actual_power_consumption = 1070 watts
    #         action = (Cannot show property)
    #
    #     Commands:
    #         cd
    #         reset
    #         set
    #         show
    #         start
    #         stop
    #
    # mrburns-rsc-> Session closed
    # Disconnected

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.entries = {}

        self.ipmitool = '/sbin/ipmitool'
        self._get_sunos_fru()
        self._get_sunos_ipmi_branch('sys', '/SYS')
        self._get_sunos_ipmi_branch('system', '/System')
        self._get_sunos_ipmi_branch('processors', '/System/Processors')
        self._get_sunos_ipmi_branch('cpu0', '/System/Processors/CPUs/CPU_0')
        self._get_sunos_ipmi_branch('memory', '/System/Memory')

    def _get_sunos_ipmi_branch(self, desc, branch):
        self.logger.info("Retreiving 'ipmitool %s' data ...", branch)
        entries = self.entries.setdefault(desc, {})
        cmd = '{} sunoem cli "show {}"'.format(self.ipmitool, branch)
        ret = __salt__['cmd.run_all'](cmd, python_shell=True)
        if ret['retcode'] != 0:
            raise CommandExecutionError(ret['stderr'])
        found_beginning = False
        for line in ret['stdout'].split('\n'):
            line = line.strip()
            # /System
            if line.startswith('/'):
                found_beginning = True
                continue
            if not found_beginning or not line:
                continue
            if line.endswith(':'):
                stanza = line[:-1]
                entries.setdefault(stanza, {})
                continue
            if ' = ' in line:
                (key, val) = line.split('=', 1)
                key = key.strip()
                val = val.strip()
                entries[stanza][key] = val
            else:
                entries[stanza][line] = ''

    def _get_sunos_fru(self):
        self.logger.info("Retreiving 'ipmitool fru' data ...")

        # FRU Device Description : Builtin FRU Device (LUN 0 ID 0)
        #  Product Manufacturer  : Oracle Corporation
        #  Product Name          : ILOM
        #  Product Version       : 4.0.3.1
        #
        # FRU Device Description : BMC
        #  Product Manufacturer  : Oracle Corporation
        #  Product Name          : ILOM
        #  Product Version       : 4.0.3.1
        #
        # FRU Device Description : /SYS (LUN 0 ID 3)
        #  Chassis Type          : Rack Mount Chassis
        #  Product Manufacturer  : Oracle Corporation
        #  Product Name          : SPARC T5-2
        #  Product Part Number   : 34117570+1+1
        #  Product Serial        : AK00352705
        #
        # FRU Device Description : FB (LUN 0 ID 212)
        #  Board Mfg Date        : Sat Nov  7 00:44:00 2015
        #  Board Mfg             : Oracle Corporation
        #  Board Product         : ASSY,FAN_MOD_BRD,G3
        #  Board Serial          : 464507N+1551HH002X
        #  Board Part Number     : 7057262
        #  Board Extra           : Rev 02

        entries = self.entries.setdefault('fru', {})
        ret = __salt__['cmd.run_all']('{} fru'.format(self.ipmitool))
        if ret['retcode'] != 0:
            raise CommandExecutionError(ret['stderr'])
        for line in ret['stdout'].split('\n'):
            line = line.strip()
            if not line or ':' not in line:
                continue
            (key, val) = line.split(':', 1)
            key = key.strip()
            val = val.strip()
            if 'FRU Device Description' in key:
                entry = val
                # Strip '(LUN ...)'
                entry = entry[:entry.find('(')]
                entry = entry.strip()
                entries.setdefault(entry, {})
                continue
            entries[entry][key] = val

    def __getitem__(self, key):
        v = self.entries
        for k in key.split(':'):
            v = v[k]
        return v


class BaseSysInfo():
    '''
    Top level SysInfo class for subclassing by OS-specific SysInfo classes.

    Methods defined here work on both Solaris and Linux.  Methods that only
    work on a particular OS should be defined in the respective OS-specific
    SysInfo class.
    '''
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Retreiving 'sysinfo' data ...")
        self.attribs = {}
        self.grains = __salt__['grains.items']()
        # Base data
        self.attribs['Data_Updated'] = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                                     time.gmtime())
        self.attribs['System_Name'] = self.grains['id']
        self.attribs['RAM'] = str(self.grains['mem_total'])
        self.cpu_model = self.grains['cpu_model']
        self.attribs['Vendor'] = self.grains['manufacturer']
        self.attribs['Serial_Number'] = self.grains['serialnumber']
        self.attribs['OVMPhysical'] = 'N/A'
        # Patch group owner and full team name
        _ = self.grains.get('ni_unix')
        if _ is None:
            self.logger.warning('ni_unix grain not found')
            ni_unix = {}
        else:
            ni_unix = _
        teams_data = __salt__['pillar.get']('provision:linux:teams')
        _ = ni_unix.get('patch_group_owner')
        if _ is None:
            pgo = 'None'
        else:
            pgo = _
        try:
            team_dict = teams_data.get(pgo)
        except AttributeError as err:
            msg = ('Pillar data provision:linux:teams was invalid, unable to '
                   'gather system data')
            raise BadResponseError(msg) from err
        if team_dict is None:
            self.logger.warning('Pillar team data not found for (%s)', pgo)
            full_team_name = pgo
        else:
            full_team_name = team_dict['full_name']
        # Non-patch owner data
        tech_owner = __salt__['pillar.get']('sysinfo:technical_owner')
        self.attribs['Owner_Technical'] = tech_owner
        if pgo == 'unix':
            self.attribs['Owner_Business'] = full_team_name
            self.attribs['Owner_Support'] = full_team_name
            self.attribs['Owner_User'] = full_team_name
        # Patch owner data
        roles = {'dev': 'Development',
                 'test': 'Test',
                 'prod': 'Production'}
        self.attribs['Production_Dev_Test'] = roles.get(ni_unix['role'], '')
        self.attribs['Patch_Group_Class'] = ni_unix.get('patch_group_class', '')
        pgo = ni_unix.get('patch_group_owner', 'None')
        self.attribs['Patch_Group_Owner'] = pgo
        epoch_start = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(0))
        self.attribs['Patch_Time'] = ni_unix.get('patch_time', epoch_start)
        self.attribs['Patch_Set'] = ni_unix.get('patch_set', 'None')
        functions = ni_unix.get('functions', [])
        self.attribs['Functions_Supported'] = '\n'.join(functions)

    @staticmethod
    def create(ostype):
        '''
        Return a SysInfo instance based on OS type
        '''
        os_map = {'SunOS': SolarisSysInfo,
                  'Linux': LinuxSysInfo}
        os_class = os_map.get(ostype)
        if os_class is None:
            raise ValueError('Invalid OS type: ({})'.format(ostype))
        return os_class()

    def __getitem__(self, key):
        try:
            return self.attribs[key]
        except KeyError:
            return None


class SolarisSysInfo(BaseSysInfo):
    '''
    Solaris-specific SysInfo class.
    '''

    def __init__(self):
        super().__init__()
        self.prtdiag = prtDiag()
        self.mpstat = MpStat()
        domain_roles = self.grains.get('virtual_subtype', '')
        tmpl = '{} x {} @ {} MHz ({})'
        # Set chassis data
        if 'control' in domain_roles:
            self.ipmitool = IPMITool()
            cpu_count, cpu_details = self._si_cpu_count(chassis=True)
            cpu_mhz = self._si_cpu_mhz(chassis=True)
            _ = self.grains['id'].replace('-pri', '')
            self.attribs['Chassis_System_Name'] = _
            self.attribs['Chassis_Model'] = self.grains['productname']
            self.attribs['Chassis_RAM'] = self._si_chassis_ram()
            self.attribs['Chassis_CPU'] = tmpl.format(cpu_count, self.cpu_model,
                                                      cpu_mhz, cpu_details)
        # Set LDOM data
        if domain_roles:
            self.attribs['Model'] = 'LDOM: {}'.format(' '.join(domain_roles))
        else:
            self.attribs['Model'] = 'LDOM: guest'
        cpu_count, cpu_details = self._si_cpu_count()
        cpu_mhz = self._si_cpu_mhz()
        self.attribs['CPU'] = tmpl.format(cpu_count, self.cpu_model, cpu_mhz,
                                          cpu_details)
        kernel = self.grains['kernel']
        kernelversion = self.grains['kernelversion']
        self.attribs['OS_Version'] = '{} {}'.format(kernel, kernelversion)
        self.attribs['Kernel_Version'] = self.grains['kernelversion']

    def _si_chassis_ram(self):
        factors = {
            'Megabytes': 1,
            'MB': 1,
            'GB': 1024,
            'TB': 1024 * 1024,
        }
        ram = self.ipmitool['memory:Properties:installed_memory']
        # pylint: disable=no-member
        qty, factor = ram.split()
        # pylint: enable=no-member
        return str(int(float(qty) * factors[factor]))

    def _si_cpu_mhz(self, chassis=False):
        factors = {
            'MHz': 1,
            'GHz': 1000,
        }
        if chassis:
            speed = self.ipmitool['cpu0:Properties:max_clock_speed']
            # pylint: disable=no-member
            qty, factor = speed.split()
            # pylint: enable=no-member
        else:
            qty, factor, _ = self.prtdiag['cpu'].split(':', 2)
        return str(int(float(qty) * factors[factor]))

    def _si_cpu_count(self, chassis=False):
        if chassis:
            sockets = self.ipmitool['processors:Properties:installed_cpus']
            if 'T4' in self.cpu_model:
                cores = 8
                threads = 8
            elif 'T5' in self.cpu_model:
                cores = 16
                threads = 8
            elif 'T7' in self.cpu_model or 'M7' in self.cpu_model:
                cores = 32
                threads = 8
            else:
                self.logger.warning("Unknown CPU model: (%s)", self.cpu_model)
            details = 'sockets:{} cores/socket:{} threads/core:{}'
            cpu_details = details.format(sockets, cores, threads)
            cpu_count = str(int(sockets) * int(cores) * int(threads))
        else:
            details = 'sockets:1 cores/socket:1 threads/core:{}'
            cpu_details = details.format(len(self.mpstat))
            cpu_count = str(len(self.mpstat))
        return (cpu_count, cpu_details)


class LinuxSysInfo(BaseSysInfo):
    '''
    Linux-specific SysInfo class.
    '''
    def __init__(self):
        super().__init__()
        if 'lsb_distrib_codename' in self.grains:
            self.attribs['OS_Version'] = self.grains['lsb_distrib_codename']
        else:
            self.attribs['OS_Version'] = self.grains['osfinger']
        self.attribs['Kernel_Version'] = self.grains['kernelrelease']
        self.attribs['Model'] = self.grains['productname']
        cpu_count = str(self.grains['num_cpus'])
        tmpl = '{} x {}'
        self.attribs['CPU'] = tmpl.format(cpu_count, self.cpu_model)
        gz_file = '/etc/globalzone'
        if __salt__['file.file_exists'](gz_file):
            ret = __salt__['cmd.run_all']('cat {}'.format(gz_file))
            if ret['retcode'] != 0:
                self.logger.warning('Error opening file %s: (%s)',
                                    gz_file, ret['stderr'])
            else:
                self.attribs['OVMPhysical'] = ret['stdout']


def systems_db():
    '''
    Gather system data for populating the systems database.

    :returns: System data mapped into subdicts based on the keys in pillar:
    "cmdb:class_attribs".
    :rtype: dict
    '''
    ret = {}
    try:
        sysinfo = BaseSysInfo.create(__grains__['kernel'])
    except BadResponseError as err:
        return str(err)
    pillar_attribs = __salt__['pillar.get']('cmdb:class_attribs')
    for class_id, pillar_attrib_list in pillar_attribs.items():
        class_attr_dict = ret.setdefault(class_id, {})
        for pillar_attrib in pillar_attrib_list:
            if sysinfo[pillar_attrib] is None:
                continue
            class_attr_dict[pillar_attrib] = sysinfo[pillar_attrib]
    return ret


def ldom_dbs():
    '''
    Get Oracle DB instances running on this system (if any).
    Intended for use on guest LDOMs.

    :returns: Oracle DB instance names, empty list if none found
    :rtype: list
    '''
    logger = logging.getLogger(__name__)
    ret = []
    functions = __salt__['grains.get']('ni_unix:functions')
    if 'rac_19c' in functions:
        # Get crsctl status output
        cmd = ('$GI_HOME/bin/crsctl stat res -t -w "(TYPE = ora.service.type) '
               'and (STATE = ONLINE) and (TARGET_SERVER = {}) and '
               '(NAME co _user.svc)"'.format(__grains__['id']))
        output = __salt__['cmd.run_all'](cmd, runas='oracle', python_shell=True)
        if output['retcode'] != 0:
            ret.append(output['stdout'])
            ret.append(output['stderr'])
            return ret
        # Parse out DB names
        for line in output['stdout'].splitlines():
            if not line.startswith('ora.'):
                continue
            s1 = line.split('.')
            s2 = s1[2].split('_')
            db_name = s2[0]
            ret.append(db_name)
    elif 'rac' in functions:
        # Get pmon PIDs
        pids = __salt__['ps.pgrep']('[o]ra_pmon', pattern_is_regex=True,
                                    full=True)
        if pids is None:
            return ret
        # Parse out DB names
        for pid in pids:
            proc_info = __salt__['ps.proc_info'](pid, attrs=['cmdline'])
            if 'ERROR' in proc_info:
                logger.warning('Error getting process info for PID (%s): %s',
                               pid, proc_info)
                continue
            clist = proc_info['cmdline']
            if not clist:
                logger.warning('No cmdline found for PID (%s)', pid)
                continue
            cmdline = clist[0]
            db_name = cmdline.rpartition('_')[2]
            ret.append(db_name)
    return ret
