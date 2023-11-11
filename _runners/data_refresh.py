# -*- coding: utf-8 -*-
'''
Runner for handling various operations related to ShadowImage data refreshes
for Oracle databases.

http://mephisto.natinst.com/twiki/bin/view/Main/DataRefreshsesDoc

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

# Import python libs
# import logging

# Import Salt libs
from salt import client

# LOG = logging.getLogger(__name__)


def _dup_check(lclient, target, horcm, devgrp):
    '''
    Check for duplicate LDEV definitions in other HORCM config files
    '''
    ldev_grp = devgrp.lower()

    dup_ret = {}
    # Read in HORCM config data for target host and get target device group
    target_data = lclient.cmd(target, 'hds_cci.get_horcm_groups',
                              [horcm])[target]
    if not target_data:
        return ('ERROR: /etc/horcm'+str(horcm)+'.conf on target host '+target+
                ' not found or not readable')
    target_dg = target_data[ldev_grp]['devices']
    # Read in HORCM configs from other DB hosts
    others_match = ('G@ni_unix:functions:si_refresh'
                    ' or ( *1 and G@ni_unix:functions:rac )'
                    ' and not '+target+
                    ' and not G@ni_unix:functions:sandbox')
    others_data = lclient.cmd(others_match, 'hds_cci.get_horcm_groups', [horcm],
                              tgt_type='compound')
    # Compare LDEVs in dev group
    for other_host, groups in others_data.items():
        if not groups:
            continue
        for group_name in groups:
            for other_ldev in groups[group_name]['devices'].values():
                for target_ldev in target_dg.values():
                    if other_ldev.lower() != target_ldev.lower():
                        continue
                    if other_host not in dup_ret:
                        dup_ret[other_host] = [other_ldev]
                    else:
                        dup_ret[other_host].append(other_ldev)

    return dup_ret


# This pylint disable is here because I couldn't figure out a way to use only
# kwargs and not have salt-run throw an exception about the function taking
# "exactly 0 arguments"
# pylint: disable=unused-argument
def precheck(*args, **kwargs):
    '''
    Run sanity checks for the specified SI device group against all other RAC DB
    hosts with names ending in 1.

    Checks are:

    * Duplicate LDEV definitions in other HORCM config files *
    If duplicate LDEVs are found, report those along with the host on which
    they are defined.

    :param list args: Unused
    :param dict kwargs: Required args:
    :str target: Target minion ID for the refresh
    :str horcm: HORCM instance number
    :str devgrp: Name of the group to check
    :rtype: dict
    :returns: Top-level keys are the check types (e.g. Duplicate LDEVs).  Values
    are dicts whose structure is determined by the check type.  If nothing is
    found for a particular check, the value will be None.

    Check return formats:

    {Duplicate LDEVs: {host: [LDEVs]}}
    '''
    lclient = client.LocalClient()
    ret = {'Duplicate LDEVs': None}

    try:
        target = kwargs.pop('target')
        horcm = kwargs.pop('horcm')
        devgrp = kwargs.pop('devgrp')
    except KeyError as keyerr:
        return 'ERROR: Missing required argument {0}'.format(keyerr)

    dup_ret = _dup_check(lclient, target, horcm, devgrp)
    if dup_ret:
        ret['Duplicate LDEVs'] = dup_ret

    return ret
# pylint: enable=unused-argument
