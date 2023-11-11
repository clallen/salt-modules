# -*- coding: utf-8 -*-
'''
Runner for handling Sparc OVM chassis/domain and related SAN storage tasks.

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

# Import python libs
import logging
import errno
import os
import pprint
import time
import yaml

# Import Salt libs
from salt import client
from salt.exceptions import CommandExecutionError
from salt.exceptions import CheckError

LCLIENT = client.LocalClient()
PILLAR_DATA = {}


def __virtual__():
    ''' Get all pillar data on module load '''
    all_data = __salt__['pillar.show_pillar']()
    if not all_data:
        log = logging.getLogger(__name__)
        log.error('Unable to get pillar data, runner module not loaded')
        return False

    PILLAR_DATA.update(all_data)
    return True


def _prog_msg(msg):
    ''' Convenience function to help reduce visual code noise '''
    __jid_event__.fire_event({'message': msg}, 'progress')


def _ping(minion_id):
    '''
    Run the ```test.ping``` execution module function to check minion
    response.

    :param str minion_id: Minion name
    :rtype: bool
    '''
    ret = LCLIENT.cmd(minion_id, 'test.ping')
    result = False
    if ret:
        if ret[minion_id]:
            result = True
    return result


class SANFrame():
    '''
    SAN frame data and operations
    '''
    def __init__(self, number, devices):
        '''
        :param str number: SAN frame number
        :param list devices: Backend device nodes (c0t...d0s2)
        :raises: ValueError: No LDEVs found for the given devices on the given
        frame
        '''
        self._ldev_ids = []
        self.number = number
        log = logging.getLogger(__name__)
        # Get LDEV IDs from backend devices
        hex_serial = PILLAR_DATA['san']['frame_data'][number]['serial_hex']
        for device in devices:
            if hex_serial in device:
                ldev_id = '{0}:{1}'.format(device[31:33], device[33:35])
                self._ldev_ids.append(ldev_id)
            else:
                log.debug('hex_serial (%s) not in device (%s)',
                          hex_serial, device)
        if not self._ldev_ids:
            raise ValueError('No LDEVs found on frame '+number+' for devices: '+
                             ', '.join(devices))

        # Get LDEV metadata
        raidcom_server = PILLAR_DATA['san']['raidcom_server']
        ret = LCLIENT.cmd(raidcom_server, 'hds_cci.get_ldevs_metadata',
                          [self.number, self._ldev_ids])[raidcom_server]
        if not isinstance(ret, dict):
            raise CommandExecutionError('Invalid return data from '
                                        'hds_cci.get_ldevs_metadata: '+str(ret))

        self.ldevs_metadata = ret

    def _ports_for_host(self, host):
        ret = set()
        for ddict in self.ldevs_metadata.values():
            for port, hosts in ddict['sharing'].items():
                if host in hosts:
                    ret.add(port)
        return list(ret)

    def dup_hostgroups(self, source, dest):
        '''
        Create hostgroups for `dest` on this instance, using ports based on
        `source`.

        :param Chassis source: Chassis object to use as source
        :param Chassis dest: Chassis object to use as destination
        :raises: CommandExecutionError: Error creating hostgroups
        '''
        raidcom_server = PILLAR_DATA['san']['raidcom_server']
        ports = self._ports_for_host(source.name)
        for port in ports:
            _prog_msg('Creating hostgroups on port '+port+', frame '+
                      self.number+ ', hosts '+', '.join(dest.svcdoms))
            kwargs = {'name': 'Check hostgroup for '+str(dest.svcdoms),
                      'inst': self.number, 'port': port,
                      'hosts_to_wwns': dest.wwns,
                      'queue': True}
            ret = LCLIENT.cmd(raidcom_server, 'state.single',
                              ['hds_storage.hostgroups_exist'],
                              kwarg=kwargs)[raidcom_server]
            try:
                _ = list(ret.values())[0]
                result = _['result']
                comment = _['comment']
            except Exception as err:
                msg = ('Invalid return value from state function '
                       'hds_storage.hostgroups_exist: '+str(ret))
                raise CommandExecutionError(msg) from err

            if not result:
                raise CommandExecutionError('Could not create hostgroups',
                                            info=comment)

    def dup_sharing(self, source, dest):
        '''
        Share this instance's LDEVs to `dest`, using ports based on `source`.

        :param Chassis source: Chassis object to use as source
        :param Chassis dest: Chassis object to use as destination
        :rtype: bool
        :returns: True if sharing changes were made
        :raises: CommandExecutionError: Error sharing storage
        '''
        # Get source ports
        ports = self._ports_for_host(source.name)
        # Share to dest
        _prog_msg('Sharing LDEVs to '+', '.join(dest.svcdoms)+', frame '+
                  self.number)
        raidcom_server = PILLAR_DATA['san']['raidcom_server']
        kwargs = {'name': 'Share to '+str(dest.svcdoms),
                  'inst': self.number, 'ldev_ids': self._ldev_ids,
                  'ports': list(ports), 'hosts': dest.svcdoms,
                  'queue': True}
        ret = LCLIENT.cmd(raidcom_server, 'state.single',
                          ['hds_storage.ldevs_shared'],
                          kwarg=kwargs)[raidcom_server]
        try:
            _ = list(ret.values())[0]
            result = _['result']
            comment = _['comment']
            changes = _['changes']
        except Exception as err:
            msg = ('Invalid return value from state function '
                   'hds_storage.ldevs_shared: '+str(ret))
            raise CommandExecutionError(msg) from err

        if not result:
            raise CommandExecutionError('Error sharing storage on frame '+
                                        self.number+' to '+
                                        ', '.join(dest.svcdoms),
                                        info=comment)

        return bool(changes)

    def unshare_ldevs(self, chassis):
        '''
        Unshare this instance's LDEVs from the given chassis.

        :param Chassis chassis: Chassis object to use in unsharing
        :rtype: bool
        :returns: True if sharing changes were made
        :raises: CommandExecutionError: Error unsharing storage
        '''
        _prog_msg('Unsharing LDEVs from '+', '.join(chassis.svcdoms)+', frame '+
                  self.number)
        raidcom_server = PILLAR_DATA['san']['raidcom_server']
        kwargs = {'name': 'Unshare from '+str(chassis.svcdoms),
                  'inst': self.number, 'ldev_ids': self._ldev_ids,
                  'hosts': chassis.svcdoms,
                  'queue': True}
        ret = LCLIENT.cmd(raidcom_server, 'state.single',
                          ['hds_storage.ldevs_unshared'],
                          kwarg=kwargs)[raidcom_server]
        try:
            _ = list(ret.values())[0]
            result = _['result']
            comment = _['comment']
            changes = _['changes']
        except Exception as err:
            msg = ('Invalid return value from state function '
                   'hds_storage.ldevs_unshared: '+str(ret))
            raise CommandExecutionError(msg) from err

        if not result:
            raise CommandExecutionError('Error unsharing storage on frame '+
                                        self.number+' from '+
                                        ', '.join(chassis.svcdoms),
                                        info=comment)

        return bool(changes)


class Chassis():
    '''
    T-Series chassis data and operations
    '''
    def __init__(self, name):
        '''
        :param str name: Chassis name (must end in "-pri")
        :raises: ValueError: Invalid name
        '''
        if not name.endswith('-pri'):
            raise ValueError('Invalid chassis name '+name+
                             '; must end in "-pri"')
        self.name = name
        self.svcdoms = [name, name.replace('-pri', '-sec')]
        _prog_msg('Gathering chassis data from '+name.split('-')[0])
        # Get local SSL cert data
        local_cert = '/var/share/ldomsmanager/server.crt'
        ret = LCLIENT.cmd(self.name, 'cp.get_file_str', [local_cert])[self.name]
        try:
            self.cert_data = ret
        except Exception as err:
            err_msg = ('Invalid return value from cp.get_file_str("'+
                       local_cert+'"): '+str(ret))
            raise CommandExecutionError(err_msg) from err
        # Ensure the trusted cert dir exists
        self.trust_dir = '/var/share/ldomsmanager/trust'
        exists = LCLIENT.cmd(name, 'file.directory_exists',
                             [self.trust_dir])[name]
        if not exists:
            LCLIENT.cmd(name, 'file.makedirs', [self.trust_dir+'/'])
        # Get service domain WWNs
        self.wwns = {name: [], name.replace('-pri', '-sec'): []}
        for svcdom, wwns in self.wwns.items():
            cmd = '/sbin/fcinfo hba-port'
            ret = LCLIENT.cmd(svcdom, 'cmd.run', [cmd])[svcdom]
            try:
                lines = ret.splitlines()
            except AttributeError as err:
                raise CommandExecutionError('Invalid return value from cmd.run '
                                            '('+cmd+') on '+svcdom+
                                            ': '+str(ret)) from err
            for line in lines:
                if not line.startswith('HBA'):
                    continue
                wwns.append(line.split(': ')[1])

    def get_ldom(self, name):
        '''
        Get a GuestLDOM instance for the given LDOM name.

        :param str name: LDOM name
        :rtype: GuestLDOM
        :raises: CheckError: LDOM not found on this chassis
        '''
        ret = LCLIENT.cmd(self.name, 'ldm.get_domains')[self.name]
        found = True
        try:
            if name not in ret:
                found = False
        except Exception as err:
            raise CommandExecutionError('Invalid return value from '
                                        'ldm.get_domains: '+str(ret)) from err
        if not found:
            raise CheckError('LDOM '+name+' not found on '+self.name)
        return GuestLDOM(name, self.name)

    def setup_cert(self, remote_chassis, force=False):
        '''
        Ensure the remote host's ldmd SSL certificate is configured on this
        host, as documented in "How to Configure SSL Certificates for Migration"
        in the "Oracle VM Server for SPARC Administration Guide".

        :param Chassis remote_chassis: Chassis object from which to get
        cert data
        :param bool force: If True, setup certificate even if it already exists.
        This is useful for when the cert has been previously configured on this
        host, but has changed for some reason (rebuild, boot environment change,
        etc).
        :raises: ValueError: Invalid remote chassis object
        :raises: CheckError: Invalid remote SSL cert data
        :raises: CommandExecutionError: ldmd service restart timed out
        '''
        if not isinstance(remote_chassis, Chassis):
            raise ValueError('Invalid remote chassis object '+
                             str(remote_chassis))
        ldmd_timeout = 600
        cert_changed = False
        _prog_msg('Setting up SSL cert from '+remote_chassis.name+' on '+
                  self.name)
        # Verify remote cert file
        remote_cert_file = self.trust_dir+'/'+remote_chassis.name+'.pem'
        exists = LCLIENT.cmd(self.name, 'file.file_exists',
                             [remote_cert_file])[self.name]
        if any([not exists, force]):
            # Write remote cert file
            LCLIENT.cmd(self.name, 'file.write', [remote_cert_file,
                                                  remote_chassis.cert_data])
            # Verify remote cert data
            cmd = '/bin/openssl verify '+remote_cert_file
            ret = LCLIENT.cmd(self.name, 'cmd.run', [cmd])[self.name]
            try:
                result = ret.lower()
            except AttributeError as err:
                raise CommandExecutionError('Invalid return value from cmd.run '
                                            '('+cmd+'): '+str(ret)) from err
            if not result.endswith('ok'):
                raise CheckError('SSL cert verify failed for '+remote_cert_file+
                                 ' on '+self.name)
            cert_changed = True
        # Verify cert CA symlink
        ca_link = '/etc/certs/CA/'+remote_chassis.name+'.pem'
        exists = LCLIENT.cmd(self.name, 'file.is_link', [ca_link])[self.name]
        if not exists:
            LCLIENT.cmd(self.name, 'file.symlink', [remote_cert_file, ca_link])
        # Restart services if cert data changed
        if cert_changed:
            LCLIENT.cmd(self.name, 'service.restart', ['ca-certificates'])
            LCLIENT.cmd(self.name, 'service.restart', ['ldmd'])
            # Wait for ldmd to restart
            _prog_msg('Waiting for ldmd restart on '+self.name)
            timer = 0
            while True:
                if timer > ldmd_timeout:
                    raise CommandExecutionError('ldmd restart timeout')
                cmd = '/bin/svcs -x ldmd'
                ret = LCLIENT.cmd(self.name, 'cmd.run', [cmd])[self.name]
                try:
                    if 'offline' not in ret:
                        break
                except Exception as err:
                    msg = ('Invalid return data from cmd.run ('+cmd+'): '+
                           str(ret))
                    raise CommandExecutionError(msg) from err
                timer += 1
                time.sleep(1)
        else:
            _prog_msg('No cert data changed, force_certs option not given')

    def add_vdsvols(self, ldom):
        '''
        Add VDS volumes associated with vdisks on the given guest LDOM.

        :param GuestLDOM ldom: GuestLDOM object from which to get VDS volume
        data
        :raises: CommandExecutionError: Problem running backend function
        '''
        _prog_msg('Adding VDS volumes associated with '+ldom.name)
        for svcdom in ['primary', 'secondary']:
            kwargs = {'name': svcdom+'-vds'+ldom.vdsnum,
                      'vdsvols': ldom.vdsvols,
                      'queue': True}
            ret = LCLIENT.cmd(self.name, 'state.single',
                              ['ldom.vdsvols_present'],
                              kwarg=kwargs)[self.name]
            try:
                _ = list(ret.values())[0]
                result = _['result']
                comment = _['comment']
            except Exception as err:
                raise CommandExecutionError('Invalid return value from state '
                                            'function ldom.vdsvols_present: '+
                                            str(ret)) from err
            if not result:
                raise CommandExecutionError('Could not add '+svcdom+
                                            ' VDS volumes', info=comment)

    def remove_vdsvols(self, ldom=None):
        '''
        Remove VDS volumes associated with vdisks on the given guest LDOM.

        :param GuestLDOM ldom: GuestLDOM object from which to get VDS volume
        data.  If None, attempt to remove all VDS volumes.
        :raises: CommandExecutionError: Problem running backend function
        '''
        kwargs_list = []
        if ldom is None:
            _prog_msg('Attempting to remove all VDS volumes')
            # Get data from ldm.get_vdsvols
            vdsvol_data = LCLIENT.cmd(self.name, 'ldm.get_vdsvols')[self.name]
            # Build kwargs list for vdsvols_absent
            for vds_name, vols_list in vdsvol_data.items():
                kwargs = {'name': vds_name, 'queue': True}
                vdsvol_names = []
                for vol in vols_list:
                    vdsvol_names.append(vol['vol'])
                kwargs['vdsvols'] = vdsvol_names
                kwargs_list.append(kwargs)
        else:
            _prog_msg('Removing VDS volumes associated with '+ldom.name)
            # Get volume names for vdsvols_absent
            vdsvol_names = []
            for vol in ldom.vdsvols:
                vdsvol_names.append(vol['vol'])
            # Build kwargs list for vdsvols_absent
            for svcdom in ['primary', 'secondary']:
                kwargs = {'name': svcdom+'-vds'+ldom.vdsnum,
                          'vdsvols': vdsvol_names,
                          'queue': True}
                kwargs_list.append(kwargs)
        # Remove vdsvols
        for kwargs in kwargs_list:
            ret = LCLIENT.cmd(self.name, 'state.single',
                              ['ldom.vdsvols_absent'],
                              kwarg=kwargs)[self.name]
            try:
                _ = list(ret.values())[0]
                result = _['result']
                comment = _['comment']
            except Exception as err:
                raise CommandExecutionError('Invalid return value from state '
                                            'function ldom.vdsvols_absent: '+
                                            str(ret)) from err
            if not result:
                raise CommandExecutionError('Could not remove '+svcdom+
                                            ' VDS volumes', info=comment)

    def refresh_storage(self):
        '''
        Run SAN refresh SLS on service domains.
        '''
        _prog_msg('Refreshing storage on '+', '.join(self.svcdoms))
        LCLIENT.cmd(self.svcdoms, 'state.sls', ['util.storage.refresh_san'],
                    tgt_type='list')

    def memory_snapshot(self, out_dir):
        '''
        Output current memory layout to a file in the given directory (on the
        master).  The file will be named <chassis>_mem_<timestamp>.
        Free memory is listed first, then memory allocated to each domain
        (including service domains).
        This is done via the ldm commands:
        ```
        ldm list-devices -p memory
        ldm list -p -o memory
        ```

        :param str out_dir: Absolute path to the directory in which to write the
        file.  It will be created if it does not exist.
        :raises: ValueError: Non-absolute output path
        :raises: IOError: Problem writing file
        :raises: CommandExecutionError: Problem running ldm command
        '''
        # Validate path
        if not out_dir.startswith('/'):
            raise ValueError('Invalid output path '+out_dir+' - must be '
                             'absolute')
        # Build output filename
        timestamp = time.strftime('%m%d%Y%H%M%S')
        out_file = out_dir+'/'+self.name+'_mem_'+timestamp
        _prog_msg('Saving memory snapshot of '+self.name+' to file '+
                  out_file+' on the Salt master')
        # Get data
        cmd = 'ldm list-devices -p memory'
        ret = LCLIENT.cmd(self.name, 'cmd.run_all', [cmd])[self.name]
        try:
            retcode = ret['retcode']
            stderr = ret['stderr']
            stdout = ret['stdout']
        except Exception as err:
            raise CommandExecutionError('Invalid return data from cmd.run_all '
                                        '('+cmd+'): '+str(ret)) from err
        if retcode:
            raise CommandExecutionError('Could not get free memory on '+
                                        self.name, info=stderr)
        free = stdout
        cmd = 'ldm list -p -o memory'
        ret = LCLIENT.cmd(self.name, 'cmd.run_all', [cmd])[self.name]
        try:
            retcode = ret['retcode']
            stderr = ret['stderr']
            stdout = ret['stdout']
        except Exception as err:
            raise CommandExecutionError('Invalid return data from cmd.run_all '
                                        '('+cmd+'): '+str(ret)) from err
        if retcode:
            raise CommandExecutionError('Could not get allocated memory on '+
                                        self.name, info=stderr)
        used = stdout
        # Write file
        try:
            os.makedirs(out_dir)
        except OSError as err:
            if err.errno != errno.EEXIST:
                raise CommandExecutionError('Unable to create path '+out_dir,
                                            info=err.strerror) from err
        out_data = free+'\n'+used
        with open(out_file, 'w', encoding='utf-8') as fobj:
            fobj.write(out_data)

    def audit_guest(self, ldom):
        '''
        Run the ```ldm.audit_guest``` execution module function on the given
        guest.

        :param GuestLDOM ldom: GuestLDOM object representing guest to audit
        :rtype: dict
        :returns: Any problems found in the audit, empty dict if none
        '''
        _prog_msg('Running pre-migration audit on '+ldom.name)
        return LCLIENT.cmd(self.name, 'ldm.audit_guest',
                           kwarg={'domnames': ldom.name})[self.name]


class GuestLDOM():
    '''
    Guest LDOM data and operations
    '''
    def __init__(self, name, chassis):
        '''
        :param str name: LDOM name
        :param str chassis: Name of the chassis this LDOM is currently on
        :raises: CheckError: Problem finding storage data
        :raises: CommandExecutionError: Problem running ldm command
        '''
        self.name = name
        self.chassis = chassis
        _prog_msg('Gathering storage data from '+name)
        # Get vdsnum
        if name[-1:].isdigit():
            self.vdsnum = str(int(name[-1:])-1)
        else:
            self.vdsnum = '0'
        # get vdisks
        vdisks = LCLIENT.cmd(chassis, 'ldm.get_vdisks', [name])[chassis]
        if not isinstance(vdisks, list):
            raise CommandExecutionError('Invalid return data from '
                                        'ldm.get_vdisks: '+str(vdisks))
        # Get vdsvols and backend devices
        ret = LCLIENT.cmd(chassis, 'ldm.get_vdsvols',
                          ['primary-vds'+self.vdsnum])[chassis]
        try:
            pri_vdsvols = list(ret.values())[0]
        except Exception as err:
            raise CommandExecutionError('Invalid return data from '
                                        'ldm.get_vdsvols: '+str(ret)) from err
        devices = []
        self.vdsvols = []
        for vdisk in vdisks:
            # Get device nodes and vdsvols
            volname = vdisk['vol'].split('@')[0]
            for vdsdict in pri_vdsvols:
                if vdsdict['vol'] == volname:
                    device = vdsdict['dev'].split('/')[3]
                    devices.append(device)
                    self.vdsvols.append(vdsdict)
                    break
        if not devices:
            raise CheckError('No backend disk devices found for '+name+
                             ' on '+chassis)
        if not self.vdsvols:
            raise CheckError('No VDS volumes found for '+name+' on '+chassis)
        # Get SAN storage data from backend devices
        self.san_frames = []
        for number in PILLAR_DATA['san']['frame_data']:
            try:
                san_frame = SANFrame(number, devices)
            except ValueError:
                continue
            self.san_frames.append(san_frame)

    def _set_trans_probing(self, state):
        '''
        Enable or disable transitive probing.

        :param bool state: True enable, False disable
        :raises: CommandExecutionError: Enable/disable operation failed
        '''
        state_bool_str = str(state).lower()
        state_cmd = '/bin/svcprop -p config/transitive-probing ipmp:default'
        cur_state = LCLIENT.cmd(self.name, 'cmd.run_stdout',
                                [state_cmd])[self.name]
        # Return if already in desired state
        if cur_state == state_bool_str:
            return
        if state:
            verb = 'Enabling'
        else:
            verb = 'Disabling'
        _prog_msg(verb+' transitive probing on '+self.name)
        LCLIENT.cmd(self.name, 'solaris_network.ipmp_trans_probe', [state])
        new_state = LCLIENT.cmd(self.name, 'cmd.run_stdout',
                                [state_cmd])[self.name]
        if new_state != state_bool_str:
            raise CommandExecutionError(verb+' transitive probing failed')

    def is_active(self):
        '''
        :rtype: bool
        :returns: True if the guest LDOM is in "active" state
        '''
        ret = LCLIENT.cmd(self.chassis, 'ldm.domain_get_state',
                          [self.name])[self.chassis]
        return ret == 'active'

    def migrate(self, target_chassis, force):
        '''
        Migrate this domain to the target chassis.

        :param str target_chassis: Migration target chassis name (must end in
        "-pri")
        :param bool force: If True, add force flag (-f) to the migrate-domain
        command
        :raises: ValueError: Invalid target chassis name
        :raises: CommandExecutionError: Migrate command failed
        :raises: CheckError: Status checking failed
        '''
        if not target_chassis.endswith('-pri'):
            raise ValueError('Invalid target chassis name '+target_chassis+
                             '; must end in "-pri"')
        # Get migration type
        live = self.is_active()
        if live:
            self._set_trans_probing(False)
        # Migration
        mig_target = target_chassis.replace('-pri', '-mig')
        force_arg = ''
        force_msg = ''
        if force:
            force_arg = '-f '
            force_msg = ' with force option '
        jobid = LCLIENT.cmd_async(self.chassis, 'cmd.run',
                                  ['/sbin/ldm migrate-domain '+force_arg+'-c '+
                                   self.name+' '+mig_target])
        if jobid == 0:
            raise CommandExecutionError('migrate-domain command failed to run')
        _prog_msg('Starting migration'+force_msg+', job ID: '+jobid)
        if live:
            # Monitor
            while True:
                cmd = '/sbin/ldm ls -o status '+self.name
                ret = LCLIENT.cmd(self.chassis, 'cmd.run', [cmd])[self.chassis]
                if any(['not found' in ret, 'STATUS' not in ret]):
                    break
                _prog_msg(ret)
                time.sleep(1)
        # Check job status
        timeout = 20
        count = 1
        while count < timeout:
            job_data = __salt__['jobs.lookup_jid'](jobid)
            if self.chassis in job_data:
                # If there was no output returned, consider it successful
                if job_data[self.chassis]:
                    raise CheckError(job_data[self.chassis])
                break
            time.sleep(1)
            count += 1
        else:
            raise CheckError('Timed out waiting for job return data ('+
                             str(timeout)+'s)')
        # Post-migration
        if live:
            # Allow time for domain resume
            time.sleep(5)
            self._set_trans_probing(True)
            # Restart HORCMs, if any
            cmd = '/bin/svcs -H svc:/site/horcm:horcm[[:digit:]]'
            ret = LCLIENT.cmd(self.name, 'cmd.run_all', [cmd])[self.name]
            try:
                retcode = ret['retcode']
                stdout = ret['stdout']
            except Exception as err:
                msg = ('Invalid return data from cmd.run_all ('+cmd+'): '+
                       str(ret))
                raise CommandExecutionError(msg) from err
            if retcode == 0:
                for line in stdout.splitlines():
                    horcm_svc = line.rpartition(':')[2]
                    _prog_msg('Restarting '+horcm_svc+' instance')
                    LCLIENT.cmd(self.name, 'service.restart', [horcm_svc])
            else:
                _prog_msg('No HORCM instances found to restart')
            # Run highstate backgrounded
            _prog_msg('Running Salt highstate')
            cmd = '/opt/apps/unix/salt/bin/salt-call state.highstate'
            LCLIENT.cmd_async(self.name, 'cmd.run', [cmd], kwargs={'bg': True})


def migrate(source_host, target_host, guest, skip='', memfile_path='/tmp',
            mem_snapshot=False, force_certs=False, force_mig=False,
            prep_only=False):
    '''
    Migrate a guest domain.  This involves all of the backend storage work,
    including adding hostgroups and sharing LDEVs as needed.  SSL certificate
    auth is also set up between the hosts.

    Memory snapshots of each chassis can be taken before and after migration
    and written to files on the Salt master, one per chassis.  The files will
    be named <chassis>_mem_<timestamp>.  See the "mem_snapshot" and
    "memfile_path" arguments.
    Free memory is listed first, then memory allocated to each domain
    (including service domains).
    This is done via the ldm commands:
    ```
    ldm list-devices -p memory
    ldm list -p -o memory
    ```

    Status messages are output as each phase starts, and percentage progress of
    the actual migration is displayed.

    :param str source_host: Host from which the guest will be migrated (must
    end in "-pri")
    :param str target_host: Host to which the guest will be migrated (must end
    in "-pri")
    :param str guest: Domain to migrate
    :param str skip: Optional comma-separated list of operations to skip:
    `hostgroups` - Skip checking/creating hostgroups
    `sharing` - Skip checking/sharing LDEVs
    `certs` - Skip checking/configuring host SSL certificates
    `all` - Skip all of the above
    :param bool force_certs: If True, setup ldmd SSL certificates even if they
    already exist.  Defaults to False.
    :param bool force_mig: If True, use the "-f" flag in the ldm migrate-domain
    command.  Defaults to False.
    :param bool prep_only: If True, do everything except migration and memory
    snapshots.  Defaults to False.
    :param bool mem_snapshot: If True, do memory snapshots.  Defaults to False.
    :param str memfile_path: Absolute path on the Salt master in which to write
    chassis memory snapshot files.  Defaults to /tmp.
    '''
    try:
        # Verify minions response
        _prog_msg('Verifying chassis minions are up')
        unresponsive = []
        if not _ping(source_host):
            unresponsive.append(source_host)
        if not _ping(target_host):
            unresponsive.append(target_host)
        if unresponsive:
            lines = [('\nUnable to continue, minions on these systems are not '
                      'responding:')]
            lines.extend(unresponsive)
            return '\n'.join(lines)
        # Get chassis objects
        src_chassis = Chassis(source_host)
        tgt_chassis = Chassis(target_host)
        # Get LDOM object
        ldom = src_chassis.get_ldom(guest)
        # Get domain state, set live state accordingly
        if ldom.is_active():
            _prog_msg('Verifying guest minion is up')
            if not _ping(guest):
                return '\nUnable to continue, guest minion is not responding'
        # SAN hostgroups
        if all(['hostgroups' not in skip,
                'all' not in skip]):
            for frame in ldom.san_frames:
                frame.dup_hostgroups(src_chassis, tgt_chassis)
        # SAN LDEV sharing
        if all(['sharing' not in skip,
                'all' not in skip]):
            changes = False
            for frame in ldom.san_frames:
                if frame.dup_sharing(src_chassis, tgt_chassis):
                    changes = True
            if changes:
                tgt_chassis.refresh_storage()
        # Add VDS volumes to target chassis
        tgt_chassis.add_vdsvols(ldom)
        # Control domain SSL certs
        if all(['certs' not in skip,
                'all' not in skip]):
            src_chassis.setup_cert(tgt_chassis, force_certs)
            tgt_chassis.setup_cert(src_chassis, force_certs)
        if prep_only:
            return '\nprep_only argument given, skipping migration'
        # Memory snapshots before
        if mem_snapshot:
            src_chassis.memory_snapshot(memfile_path)
            tgt_chassis.memory_snapshot(memfile_path)
        # Guest audit
        audit = src_chassis.audit_guest(ldom)
        if audit:
            audit_out = []
            for key, val in audit[ldom.name].items():
                line = key+': '+pprint.pformat(val)
                audit_out.append(line)
            return '\nGuest audit failed:\n'+audit_out
        # Migrate
        ldom.migrate(target_host, force_mig)
        # Memory snapshots after
        if mem_snapshot:
            src_chassis.memory_snapshot(memfile_path)
            tgt_chassis.memory_snapshot(memfile_path)
    except (CheckError, CommandExecutionError, ValueError, IOError) as err:
        return '\n'+str(err)
    return '\nMigration complete'


def ldom_storage_cleanup(old_host, current_host, guest):
    '''
    Remove VDS volumes and backend storage for specified guest from specified
    host.
    WARNING: This includes shared storage which might be in use by other guests
    on that host (e.g. ASM disks).
    *VERIFY ALL STORAGE IS NOT IN USE ON THE OLD HOST BEFORE USING THIS
    FUNCTION!*

    :param str old_host: Host from which to remove VDS volumes and storage
    :param str current_host: Host from which to get VDS and storage data
    :param str guest: Guest from which to get vdisk data
    '''
    try:
        # get chassis objects
        cur_chassis = Chassis(current_host)
        old_chassis = Chassis(old_host)
        # get LDOM object
        ldom = cur_chassis.get_ldom(guest)
        # remove VDS volumes from old chassis
        old_chassis.remove_vdsvols(ldom)
        # unshare backend storage
        for frame in ldom.san_frames:
            changes = frame.unshare_ldevs(old_chassis)
        if changes:
            old_chassis.refresh_storage()
    except (CheckError, CommandExecutionError, ValueError) as err:
        return '\nERROR: '+str(err)
    return '\nStorage cleanup complete'


def chassis_storage_cleanup(svcdom, cmddevs=None, refresh_san=True):
    '''
    Attempt to unshare all storage currently shared to the given service domain.

    Since the frames will not allow unsharing for storage that has recently been
    used this may not always work.  It can be run multiple times to cleanup
    storage that may have been locked by the frame.

    A preliminary check will be done to verify that no LDOMs are defined, and
    will exit if any are found.

    All VDS volumes will also be removed.

    :param str svcdom: Name of the service domain to be cleaned up
    :param str cmddevs: Comma-separated list of LDEV IDs which will not be
    unshared.  This is intended to skip dedicated command devices.
    If None, all devices will be unshared.  Default is None.
    :param bool refresh_san: Run the SAN storage refresh code
    (util.storage.refresh_san) after successful cleanup, default is True
    :rtype: str
    :returns: Results of unsharing attempts, or error message if guest domains
    are found
    '''
    log = logging.getLogger(__name__)
    ctrldom = svcdom.replace('-sec', '-pri')
    ret = __salt__['salt.execute'](ctrldom, 'ldm.get_domains')[ctrldom]
    if len(ret) > 2:
        return '\nChassis is not empty, exiting'
    ret = __salt__['salt.execute'](svcdom, 'hds_cci.hds_scan')[svcdom]
    if not ret:
        return '\nNo shared LDEVs found'
    cmddevs_upper = []
    if cmddevs is not None:
        for cmddev in cmddevs.split(','):
            if ':' not in cmddev:
                return 'Invalid LDEV ID: '+cmddev
            cmddevs_upper.append(cmddev.upper())
    raidcom_server = PILLAR_DATA['san']['raidcom_server']
    # Map SAN frame serial number to HORCM instance
    serial_to_inst = {}
    for inst, fdict in PILLAR_DATA['san']['frame_data'].items():
        serial_dec = fdict['serial_dec']
        serial_to_inst[serial_dec] = inst
    # Map HORCM instance to LDEV IDs
    inst_to_ldevs = {}
    for ldict in ret:
        ldev_id = ldict['id']
        if ldev_id in cmddevs_upper:
            continue
        serial_dec = ldict['serial_dec']
        inst = serial_to_inst[serial_dec]
        if inst not in inst_to_ldevs:
            inst_to_ldevs[inst] = []
        inst_to_ldevs[inst].append(ldev_id)
    # Unshare LDEVs
    results = []
    changes = False
    for inst, id_list in inst_to_ldevs.items():
        args = [inst, id_list]
        kwargs = {'hosts': [svcdom]}
        ret = __salt__['salt.execute'](raidcom_server, 'hds_cci.unshare_ldevs',
                                       arg=args, kwarg=kwargs)[raidcom_server]
        log.debug('ret for hds_cci.unshare_ldevs: %s', ret)
        if not isinstance(ret, dict):
            return ('Invalid return data when unsharing LDEVs: '+
                    str(id_list)+'\nData: '+str(ret))
        for ldev, result_dict in ret.items():
            try:
                unshared = result_dict['unshared']
            except KeyError:
                return ('Invalid return data when unsharing LDEVs: '+
                        str(id_list)+'\nData: '+str(ret))
            if unshared:
                changes = True
                results.append('Unshared LDEV '+ldev+' on ports '+
                               ', '.join(unshared))
    # Remove all VDS volumes
    chassis = Chassis(ctrldom)
    chassis.remove_vdsvols()
    # Build output message
    output = []
    yaml_str = yaml.dump_all(results).replace('!!python/unicode ', '')
    if yaml_str:
        output.append(yaml_str)
    # Refresh chassis storage
    if all([refresh_san, changes]):
        __salt__['salt.execute'](svcdom, 'state.sls',
                                 arg=['util.storage.refresh_san'])
        output.append('SAN storage refreshed')
    if not output:
        output.append('Nothing to do')
    return '\n\n'.join(output)
