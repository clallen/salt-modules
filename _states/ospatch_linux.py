# -*- coding: utf-8 -*-
'''
State module for handling Linux pre and post patching tasks, which are generally
too complex for SLS and/or have render/execution timing issues.

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import
import pprint
import re
import time
# pylint: disable=too-many-branches,too-many-statements,too-many-return-statements


# "In-progress" patching grain
PATCHING_GRAIN = 'cache:patching'
# Quarter regex
Q_REGEX = r'2\d{3}q[1,3]'


def __virtual__():
    '''
    Only run on Linux
    '''
    if __grains__['os_family'] == 'RedHat':
        return True
    return False, 'This module must be run on Linux'


def _error_email(body):
    # Mail the error
    recip_list = __salt__['pillar.get']('ospatch:notify:recipients')
    recipients = ','.join(recip_list)
    error_subject = __salt__['pillar.get']('ospatch:notify:error_subject')
    __salt__['smtp.send_msg'](recipients, body, subject=error_subject,
                              profile='smtp_default')
    # Remove patching grain
    __salt__['grains.set'](PATCHING_GRAIN, val=None, force=True,
                           destructive=True)


def _rootfs_check():
    disk_usage = __salt__['disk.usage']()
    cap_ret = disk_usage['/']['capacity']
    cap_str = cap_ret.strip('%')
    ret = {'result': True}
    if int(cap_str) > 89:
        error_msg = ('Root filesystem (/) is '+cap_ret+' full, unable to '
                     'patch.  Free up disk space and try patching again.')
        _error_email(error_msg)
        ret['comment'] = error_msg
        ret['result'] = False
    return ret


def pre_patched(name=None, force=False, download=True):
    '''
    Ensure the system is pre-patched.

    :param str name: Quarterly patching release (e.g. 2018Q3).  If None, the
    pillar default will be used (ospatch:quarter).
    :param bool force: If True, attempt pre-patching even if system is
    already at the specified quarterly release.  Default is False.
    :param bool download: If True, run "yum update" with the "downloadonly"
    option.  Default is True.
    '''
    changedict = {}
    # Determine quarter
    if name is None:
        quarter = __salt__['pillar.get']('ospatch:quarter')
    else:
        quarter = name.upper()
    # Current (old) quarter
    cur_quarter = __salt__['grains.get']('ni_unix:patch_set')
    # Setup return data
    ret = {'name': quarter,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    # Check OS version
    os_versions = __salt__['pillar.get']('postinst:linux:supported:versions')
    if __grains__['osmajorrelease'] not in os_versions:
        error_msg = 'Unsupported OS version: '+str(__grains__['osmajorrelease'])
        _error_email(error_msg)
        ret['comment'] = error_msg
        ret['result'] = False
        return ret
    # Check patching grain
    patching_grain = __salt__['grains.get'](PATCHING_GRAIN)
    if patching_grain:
        timestamp = time.asctime(time.localtime(patching_grain))
        ret['comment'] = 'Patching is in progress, started '+timestamp
        ret['result'] = False
        return ret
    # Check for invalid quarter
    if re.match(Q_REGEX, quarter, re.I) is None:
        error_msg = ('Invalid quarter requested: '+quarter+', must match '
                     '[YYYY]Q1 or [YYYY]Q3')
        _error_email(error_msg)
        ret['comment'] = error_msg
        ret['result'] = False
        return ret
    if not force:
        # Check current patch set
        if not cur_quarter:
            error_msg = ('ni_unix:patch_set grain not found, contact the Unix '
                         'team for help')
            _error_email(error_msg)
            ret['comment'] = error_msg
            ret['result'] = False
            return ret
        if cur_quarter.upper() == quarter:
            ret['comment'] = 'System is already at patch set '+quarter
            return ret
    # Check pre-patch grain
    pre_patch_grain = 'cache:pre_patch'
    if __salt__['grains.get'](pre_patch_grain) == quarter:
        ret['comment'] = 'Prepatching already done'
        return ret
    # Determine repos to disable
    repolist = __salt__['pillar.get']('ospatch:linux:disable_repos')
    if repolist:
        disable_repos = ','.join(repolist)
    else:
        disable_repos = ''
    # Clear yum cache
    yum_cache_dir = '/var/cache/yum'
    if not __opts__['test']:
        out = __states__['file.absent'](yum_cache_dir)
        # The "result" field is a boolean
        if not out['result']:
            error_msg = 'Problem removing '+yum_cache_dir+': '+out['comment']
            _error_email(error_msg)
            ret['comment'] = error_msg
            ret['result'] = False
            return ret
    changedict['dir removed'] = '/var/cache/yum'
    # Check rootfs space
    rcheck = _rootfs_check()
    if not rcheck['result']:
        ret.update(rcheck)
        return ret
    # Set patching grain
    if not __opts__['test']:
        __salt__['grains.set'](PATCHING_GRAIN, val=int(time.time()),
                               force=True)
    # Check kernel-transition package
    kernel_type_grain = 'ni_unix:ospatch:kernel_type'
    if __grains__['os'] == 'OEL':
        kernel_type = __salt__['grains.get'](kernel_type_grain)
        if not kernel_type:
            error_msg = ('Grain '+kernel_type_grain+' not set.  Contact the '
                         'Unix team to determine the correct kernel type '
                         'and set this grain.  Once that is done, run patching '
                         'again.')
            _error_email(error_msg)
            ret['comment'] = error_msg
            ret['result'] = False
            return ret
        if kernel_type == 'uek':
            rm_kernel_type = 'kernel'
            if not __opts__['test']:
                # Check rootfs space
                rcheck = _rootfs_check()
                if not rcheck['result']:
                    ret.update(rcheck)
                    return ret
                # Install kernel-transition package
                out = __states__['pkg.installed']('kernel-transition')
                if not out['result']:
                    error_msg = ('Problem installing kernel-transition '
                                 'package: '+out['comment'])
                    _error_email(error_msg)
                    ret['comment'] = error_msg
                    ret['result'] = False
                    return ret
            changedict['package installed'] = 'kernel-transition'
        else:
            rm_kernel_type = 'kernel-uek'
            if not __opts__['test']:
                # Remove kernel-transition package
                out = __states__['pkg.removed']('kernel-transition')
                if not out['result']:
                    error_msg = ('Problem removing kernel-transition package: '+
                                 out['comment'])
                    _error_email(error_msg)
                    ret['comment'] = error_msg
                    ret['result'] = False
                    return ret
            changedict['package removed'] = 'kernel-transition'
        # Remove invalid kernels
        if not __opts__['test']:
            out = __states__['pkg.removed'](rm_kernel_type)
            if not out['result']:
                error_msg = (out['comment']+'  Check that grain '+
                             kernel_type_grain+' is correct.')
                _error_email(error_msg)
                ret['comment'] = error_msg
                ret['result'] = False
                return ret
        changedict['kernels removed'] = rm_kernel_type
    # Build new channel string
    channel_os = __salt__['pillar.get']('ospatch:linux:distro_channels:'+
                                        __grains__['os'])
    if not channel_os:
        error_msg = 'Unsupported distro: '+__grains__['os']
        _error_email(error_msg)
        ret['comment'] = error_msg
        ret['result'] = False
        return ret
    new_channel = (channel_os+str(__grains__['osmajorrelease'])+'-'+
                   quarter.lower()+'-x86_64')
    # Get spacewalk channels
    list_cmd = '/usr/sbin/spacewalk-channel -l'
    out = __salt__['cmd.run'](list_cmd)
    # Check for unregistered system
    if 'Invalid System Credentials' in out:
        # Try to re-register with current (old) activation key
        key = '1-{}-{}-64-{}'.format(channel_os, __grains__['osmajorrelease'],
                                     cur_quarter.lower())
        cmd = '/usr/sbin/rhnreg_ks --force --activationkey={}'.format(key)
        out = __salt__['cmd.run'](cmd)
        if 'Error' in out:
            error_msg = 'Problem re-registering system:\n{}'.format(out)
            _error_email(error_msg)
            ret['comment'] = error_msg
            ret['result'] = False
            return ret
        # Try getting spacewalk channels again
        out = __salt__['cmd.run_all'](list_cmd)
        if out['retcode'] != 0:
            tmpl = 'Problem getting current OLM channels:\n\n{}\n\n{}'
            error_msg = tmpl.format(out['stderr'], out['stdout'])
            _error_email(error_msg)
            ret['comment'] = error_msg
            ret['result'] = False
            return ret
    # Update quarterly channel
    sw_user = __salt__['pillar.get']('ospatch:linux:olm_user')
    sw_pass = __salt__['pillar.get']('ospatch:linux:olm_pass')
    cur_channels = out.splitlines()
    for channel in cur_channels:
        if re.search(Q_REGEX, channel) is None:
            continue
        if channel != new_channel:
            if not __opts__['test']:
                # Remove old channel
                cmd = ('/usr/sbin/spacewalk-channel -r -c '+channel+' -u '+
                       sw_user+' -p '+sw_pass)
                out = __salt__['cmd.run_all'](cmd)
                if out['retcode'] != 0:
                    error_msg = ('Problem removing OLM channel '+channel+
                                 ': '+out['stderr'])
                    _error_email(error_msg)
                    ret['comment'] = error_msg
                    ret['result'] = False
                    return ret
            changedict['channel removed'] = channel
    if new_channel not in cur_channels:
        if not __opts__['test']:
            # Add new channel
            out = __salt__['cmd.run_all']('/usr/sbin/spacewalk-channel -a -c '+
                                          new_channel+' -u '+sw_user+' -p '+
                                          sw_pass)
            if out['retcode'] != 0:
                error_msg = ('Problem adding OLM channel '+new_channel+
                             ': '+out['stderr'])
                _error_email(error_msg)
                ret['comment'] = error_msg
                ret['result'] = False
                return ret
        changedict['channel added'] = new_channel
    # Check rootfs space
    rcheck = _rootfs_check()
    if not rcheck['result']:
        ret.update(rcheck)
        return ret
    # Download packages
    if not __opts__['test']:
        if download:
            out = __states__['pkg.uptodate']('Download packages',
                                             nogpgcheck=True,
                                             downloadonly=True,
                                             disablerepo=disable_repos)
            if not out['result']:
                error_msg = 'Problem downloading packages: '+out['comment']
                _error_email(error_msg)
                ret['comment'] = error_msg
                ret['result'] = False
                return ret
        # Set pre-patch grain
        __salt__['grains.set'](pre_patch_grain, val=quarter)
    changedict['pre-patch grain'] = quarter
    changedict['new packages'] = 'downloaded'
    # Test output
    if __opts__['test']:
        comment = []
        comment.append('Would be changed:')
        comment.append(pprint.pformat(changedict))
        ret['comment'] = '\n'.join(comment)
    else:
        # Remove patching grain
        __salt__['grains.set'](PATCHING_GRAIN, val=None, force=True,
                               destructive=True)
    return ret


def patched(name=None, force=False):
    '''
    Ensure the system is patched.

    :param str name: Quarterly patching release (e.g. 2018Q3).  If None, the
    pillar default will be used (ospatch:quarter).
    :param bool force: If True, attempt patching even if system is already at
    the specified quarterly release.  Default is False.
    '''
    changedict = {}
    # Determine quarter
    if name is None:
        quarter = __salt__['pillar.get']('ospatch:quarter')
    else:
        quarter = name.upper()
    # Setup return data
    ret = {'name': quarter,
           'comment': ''}
    if __opts__['test']:
        ret['changes'] = {}
        ret['result'] = None
    else:
        ret['changes'] = changedict
        ret['result'] = True
    # Check OS version
    os_versions = __salt__['pillar.get']('postinst:linux:supported:versions')
    if __grains__['osmajorrelease'] not in os_versions:
        error_msg = 'Unsupported OS version: '+str(__grains__['osmajorrelease'])
        _error_email(error_msg)
        ret['comment'] = error_msg
        ret['result'] = False
        return ret
    # Check patching grain (epoch seconds)
    patching_grain = __salt__['grains.get'](PATCHING_GRAIN)
    if patching_grain:
        human_time = time.asctime(time.localtime(patching_grain))
        ret['comment'] = 'Patching is in progress, started '+human_time
        ret['result'] = False
        return ret
    # Check for invalid quarter
    if re.match(Q_REGEX, quarter, re.I) is None:
        error_msg = ('Invalid quarter requested: '+quarter+', must match '
                     '[YYYY]Q1 or [YYYY]Q3')
        _error_email(error_msg)
        ret['comment'] = error_msg
        ret['result'] = False
        return ret
    if not force:
        # Check current patch set
        cur_quarter = __salt__['grains.get']('ni_unix:patch_set')
        if not cur_quarter:
            error_msg = ('ni_unix:patch_set grain not found, contact the Unix '
                         'team for help')
            _error_email(error_msg)
            ret['comment'] = error_msg
            ret['result'] = False
            return ret
        if cur_quarter.upper() == quarter:
            ret['comment'] = 'System is already at patch set: '+quarter
            return ret
    # Patch
    if not __opts__['test']:
        # Determine repos to disable
        repolist = __salt__['pillar.get']('ospatch:linux:disable_repos')
        if repolist:
            disable_repos = ','.join(repolist)
        else:
            disable_repos = ''
        # Set environment variable to bypass typing "YES" interactively for the
        # idiotic mssql packages
        __states__['environ.setenv']('ACCEPT_EULA', 'y')
        # Check rootfs space
        rcheck = _rootfs_check()
        if not rcheck['result']:
            ret.update(rcheck)
            return ret
        # Update yum
        out = __states__['pkg.latest']('yum', nogpgcheck=True)
        if not out['result']:
            error_msg = 'Problem upgrading yum: '+out['comment']
            _error_email(error_msg)
            ret['comment'] = error_msg
            ret['result'] = False
            return ret
        changedict['yum updated'] = True
        # Check rootfs space
        rcheck = _rootfs_check()
        if not rcheck['result']:
            ret.update(rcheck)
            return ret
        # Set patching grain (epoch seconds)
        __salt__['grains.set'](PATCHING_GRAIN, val=int(time.time()),
                               force=True)
        # Do package updates
        out = __states__['pkg.uptodate']('Upgrade packages',
                                         nogpgcheck=True,
                                         disablerepo=disable_repos)
        if not out['result']:
            error_msg = 'Problem upgrading packages: '+out['comment']
            _error_email(error_msg)
            ret['comment'] = error_msg
            ret['result'] = False
            return ret
        if 'up-to-date' in out['comment']:
            ret['comment'] = 'No package updates available'
        else:
            changedict['Packages updated'] = True
    # Set patch grains
    __salt__['grains.set']('ni_unix:patch_set', val=quarter, force=True)
    changedict['Grain ni_unix:patch_set updated'] = quarter
    # patch_time is a timestamp in UTC
    tstamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    __salt__['grains.set']('ni_unix:patch_time', val=tstamp, force=True)
    changedict['Grain ni_unix:patch_time updated'] = tstamp
    # Test output
    if __opts__['test']:
        comment = []
        comment.append('Would be changed:')
        comment.append(pprint.pformat(changedict))
        ret['comment'] = '\n'.join(comment)
    else:
        # Remove patching grain
        __salt__['grains.set'](PATCHING_GRAIN, val=None, force=True,
                               destructive=True)
    return ret
