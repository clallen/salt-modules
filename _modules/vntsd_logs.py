# -*- coding: utf-8 -*-
'''
Execution module for auditing and managing vntsd logs

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

# Import Python libs
# import logging
import os
from collections import OrderedDict  # pylint: disable=minimum-python-version

# LOG = logging.getLogger(__name__)
GDU = '/bin/gdu'
TOPDIR = '/var/log/vntsd'


def __virtual__():
    '''
    Only run on T-Series SPARC control domain
    '''
    if (
            __grains__['cpu_model'] != 'SPARC-T4' and
            __grains__['cpu_model'] != 'SPARC-T5' and
            __grains__['cpu_model'] != 'SPARC-M7'
       ):
        return False, 'This module must be run on T-Series SPARC.'
    if __salt__['cmd.run_stdout']('/usr/sbin/virtinfo -c current get'+
                                  ' -H -o value control-role',
                                  output_loglevel='quiet') == 'false':
        return False, 'This module must be run on an LDOMs control domain.'
    return True


def _orphaned():
    '''
    Return log dirs that are on this chassis but have no corresponding domain

    :rtype: dict
    :returns: Key: domain name, Value: space used by log dir in bytes
    '''
    ret = OrderedDict()
    cur_doms = list(__salt__['ldm.get_domains']().keys())
    logdirs = os.listdir(TOPDIR)
    orphans = set(logdirs).difference(cur_doms)
    if not orphans:
        return ret
    orph_dirs = ['{0}/{1}'.format(TOPDIR, orphan) for orphan in orphans]
    output = __salt__['cmd.run_stdout'](GDU+' -bs '+' '.join(orph_dirs),
                                        output_loglevel='quiet')
    for line in output.splitlines():
        domname = line.split('/')[4]
        size = line.split()[0]
        ret[domname] = int(size)

    return ret


def _scale(nbytes):
    '''
    Convert to nearest 1024 string

    :param int nbytes: Bytes to convert
    :rtype: str
    :returns: Converted number with "human-readable" suffix
    '''
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    i = 0
    while nbytes >= 1024 and i < len(suffixes)-1:
        nbytes /= 1024.
        i += 1
    nfloat = ('{:.2f}'.format(nbytes)).rstrip('0').rstrip('.')
    return '{0} {1}'.format(nfloat, suffixes[i])


def get_orphaned(scaled=True):
    '''
    Return log dirs that are on this chassis but have no corresponding domain

    :param bool scaled: Scale output to nearest 1024 (aka human-readable)
    :rtype: dict
    :returns: Key: domain name, Value: space used by log dir
    '''
    orphaned = _orphaned()
    if not orphaned:
        return {}
    total = sum(orphaned.values())
    if scaled:
        ret = OrderedDict()
        for orphan in orphaned:
            size = _scale(orphaned[orphan])
            ret[orphan] = size
        ret['total'] = _scale(total)
    else:
        ret = orphaned
        ret['total'] = total

    return ret


def remove_orphaned():
    '''
    Remove log dirs that are on this chassis but have no corresponding domain
    '''
    orphans = _orphaned()
    for orphan in orphans:
        __salt__['file.remove'](TOPDIR+'/'+orphan)
