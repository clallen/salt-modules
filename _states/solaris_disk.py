# -*- coding: utf-8 -*-
'''
State module for managing Solaris disk formatting and partitioning.

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import
import logging
import pprint

LOG = logging.getLogger(__name__)


def __virtual__():
    '''
    Only run on Solaris 11 or up
    '''
    if all([__grains__['kernel'] == 'SunOS',
            __grains__['kernelrelease'] == '5.11']):
        return True
    return False, 'This module must be run on Solaris 11 or up.'


def disks_formatted(name, disk_ids, label_type='vtoc'):
    '''
    Ensure the specified disks are formatted with the given label type.

    :param str name: Salt state name
    :param list disk_ids: Disk device IDs, e.g. "10" for "c1d10"
    :param str label_type: One of: vtoc, efi
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
    if not disk_ids:
        ret['comment'] = 'Disk ID list is empty'
        ret['result'] = False
        return ret

    changed = []
    unchanged = []
    for disk_id in disk_ids:
        device = 'c1d'+disk_id
        if not __salt__['file.is_link']('/dev/rdsk/'+device+'s2'):
            ret['comment'] = '/dev/rdsk/'+device+' not found'
            ret['result'] = False
            return ret

        retcode = __salt__['cmd.retcode']('/usr/sbin/prtvtoc -h /dev/rdsk/'+
                                          device+'s2', output_loglevel='quiet')
        if retcode:
            if not __opts__['test']:
                output = __salt__['cmd.run_all']('/usr/sbin/format -L '+
                                                 label_type+' -d '+device,
                                                 output_loglevel='quiet')
                if output['retcode']:
                    ret['comment'] = output['stderr']
                    ret['result'] = False
                    return ret

            changed.append(device)
        else:
            unchanged.append(device)
    if __opts__['test']:
        comment = []
        if changed:
            comment.append('Would be formatted:')
            comment.append(pprint.pformat(changed))
        if unchanged:
            comment.append('Would be unchanged:')
            comment.append(pprint.pformat(unchanged))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if changed:
            changedict['formatted'] = changed
            if unchanged:
                changedict['unchanged'] = unchanged
    return ret


def disks_partitioned(name, disk_ids):
    '''
    Ensure the specified disks are "whole-disk" partitioned (i.e. all space
    allocated to slice 2).

    :param str name: Salt state name
    :param list disk_ids: Disk device IDs, e.g. "10" for "c1d10"
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
    if not disk_ids:
        ret['comment'] = 'Disk ID list is empty'
        ret['result'] = False
        return ret

    changed = []
    unchanged = []
    for disk_id in disk_ids:
        device = 'c1d'+disk_id
        if not __salt__['file.is_link']('/dev/rdsk/'+device+'s2'):
            ret['comment'] = '/dev/rdsk/'+device+' not found'
            ret['result'] = False
            return ret

        # Get initial VTOC
        prtvtoc_cmd = '/usr/sbin/prtvtoc /dev/rdsk/'+device+'s2'
        vtoc_out = __salt__['cmd.run_stdout'](prtvtoc_cmd,
                                              output_loglevel='quiet')
        # Reset label if needed
        if all(['sectors/cylinder' not in vtoc_out,
                'accessible cylinders' not in vtoc_out]):
            cmd = '/usr/sbin/format -L vtoc -d '+device
            cmd_out = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
            if cmd_out['retcode']:
                ret['comment'] = cmd_out['stderr']
                ret['result'] = False
                return ret

            vtoc_out = __salt__['cmd.run_stdout'](prtvtoc_cmd,
                                                  output_loglevel='quiet')
        # Calculate fmthard input string
        for line in vtoc_out.splitlines():
            if 'sectors/cylinder' in line:
                sect_per_cyl = int(line.split()[1])
                continue
            if 'accessible cylinders' in line:
                total_cyl = int(line.split()[1])
                break
        sect_count = sect_per_cyl*total_cyl-sect_per_cyl
        fmthard_input = '0 0 00 '+str(sect_per_cyl)+' '+str(sect_count)
        # Check partition table
        output = __salt__['cmd.run_stdout']('/usr/sbin/prtvtoc -h /dev/rdsk/'+
                                            device+'s2',
                                            output_loglevel='quiet')
        vtoc_out = output.splitlines()[0]
        cur_sect_per_cyl = vtoc_out.split()[3]
        cur_sect_count = vtoc_out.split()[4]
        if any([cur_sect_per_cyl != str(sect_per_cyl),
                cur_sect_count != str(sect_count)]):
            if not __opts__['test']:
                cmd = ('/bin/echo "'+fmthard_input+'" | /usr/sbin/fmthard -s - '
                       '/dev/rdsk/'+device+'s2')
                output = __salt__['cmd.run_all'](cmd, output_loglevel='quiet')
                if output['retcode']:
                    ret['comment'] = output['stderr']
                    ret['result'] = False
                    return ret

            changed.append(device)
        else:
            unchanged.append(device)
    if __opts__['test']:
        comment = []
        if changed:
            comment.append('Would be partitioned:')
            comment.append(pprint.pformat(changed))
        if unchanged:
            comment.append('Would be unchanged:')
            comment.append(pprint.pformat(unchanged))
        if comment:
            ret['comment'] = '\n'.join(comment)
    else:
        if changed:
            changedict['partitioned'] = changed
            if unchanged:
                changedict['unchanged'] = unchanged
    return ret
