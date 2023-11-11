# -*- coding: utf-8 -*-
'''
Runner module to provide data and functionality for automated Linux OS patching.
Intended to be called from the REST API by external frontend systems.

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

import logging
from salt import client


PILLAR = {}


def __virtual__():
    log = logging.getLogger(__name__)
    pillar = __salt__['pillar.show_pillar']()
    if not pillar:
        return (False, 'Unable to get pillar data')
    teams_data = pillar['provision']['linux']['teams']
    PILLAR['owners'] = {}
    for pgo_grain, ddict in teams_data.items():
        full_name = ddict.get('full_name')
        if full_name is None:
            log.debug('Patch group owner (%s) data: %s', pgo_grain, ddict)
            msg = 'Unable to get full_name for patch group owner %s'
            return (False, msg.format(pgo_grain))
        PILLAR['owners'][full_name] = pgo_grain
    PILLAR['os_versions'] = pillar['postinst']['linux']['supported']['versions']
    PILLAR['quarter'] = pillar['ospatch']['quarter']
    return True


def noncompliant(owner):
    '''
    Return hosts that are not on the current patch set.
    Filtering criteria:
        * owner matches ni_unix:patch_group_owner
        * ni_unix:patch_set grain does not match pillar data: ospatch:quarter
        * osmajorrelease grain has a match in pillar data: ospatch:os_versions

    :param str owner: System owner to match, must be in pillar data:
        provision:linux:teams
    :rtype: dict
    :returns: One of two key/values:
        * hosts: list of matching hosts (empty if no matches)
        * owners: list of valid owners (if an invalid owner argument is given)
    '''
    log = logging.getLogger(__name__)
    # Validate owner
    if owner not in PILLAR['owners']:
        full_names = list(PILLAR['owners'])
        full_names.sort()
        ret = {'owners': full_names}
    # Find matching hosts
    else:
        pgo_grain = PILLAR['owners'][owner]
        lclient = client.LocalClient()
        tgt_tmpl = ('G@ni_unix:patch_group_owner:{} and '
                    'not G@ni_unix:patch_set:{} and ( {} )')
        vers_list = []
        for version in PILLAR['os_versions']:
            vers_list.append('G@osmajorrelease:{}'.format(version))
        target = tgt_tmpl.format(pgo_grain, PILLAR['quarter'],
                                 ' or '.join(vers_list))
        log.debug('target: %s', target)
        ping_ret = lclient.cmd(target, 'test.ping', tgt_type='compound')
        log.debug('test.ping return: %s', ping_ret)
        hosts = list(ping_ret.keys())
        hosts.sort()
        ret = {'hosts': hosts}
    return ret
