# -*- coding: utf-8 -*-
'''
State module for managing guest LDOMs.

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import
from salt.exceptions import CommandExecutionError


def __virtual__():
    '''
    Only run on Solaris 11 or up
    '''
    if all([__grains__['kernel'] == 'SunOS',
            __grains__['kernelrelease'] == '5.11']):
        return True
    return False, 'This module must be run on Solaris 11 or up.'


def ipmp_group_exists(name, datalinks, ipaddr):
    '''
    Ensure an IPMP group defined by input args exists.

    :param str name: IPMP group name
    :param list datalinks: Names of datalinks to be in the IPMP group
    :param str ipaddr: IPv4 CIDR address to assign (e.g. 192.168.34.12/24).
    If None, no address is assigned
    '''
    changedict = {}
    ret = {'name': name,
           'changes': changedict,
           'comment': ''}
    if __opts__['test']:
        ret['result'] = None
    else:
        ret['result'] = True
    try:
        cur_ifs = __salt__['solaris_network.get_interfaces']()
        if name in cur_ifs:
            return ret
        cur_links = __salt__['solaris_network.get_datalinks']()
        for datalink in datalinks:
            if datalink not in cur_links:
                ret['comment'] = 'Datalink '+datalink+' does not exist'
                ret['result'] = False
                return ret
        if not __opts__['test']:
            __salt__['solaris_network.ipmp_create'](name, datalinks, ipaddr)
        changedict['new'] = 'Created'
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
    return ret


def ipmp_datalink_exists(name, datalink):
    '''
    Ensure a datalink is a member of an IPMP group.

    :param str name: IPMP group name
    :param str datalink: Datalink to check and add if necessary
    '''
    changedict = {}
    ret = {'name': name,
           'changes': changedict,
           'comment': ''}
    if __opts__['test']:
        ret['result'] = None
    else:
        ret['result'] = True
    try:
        # Get current datalinks in group
        datalinks = __salt__['solaris_network.ipmp_get_datalinks'](name)
        # Check if datalink is in group
        if datalink in datalinks:
            ret['comment'] = ('Datalink '+datalink+' is already in group '+name)
        else:
            if not __opts__['test']:
                __salt__['solaris_network.ipmp_add'](name, [datalink])
            changedict['new'] = datalink
    except (ValueError, CommandExecutionError) as err:
        ret['comment'] = str(err)
        ret['result'] = False
    return ret


def ip_addr_exists(name, ipaddr):
    '''
    Ensure an IP address exists on the specified datalink.  An IP stack will be
    created first if needed.

    :param str name: Datalink name
    :param str ipaddr: IPv4 CIDR address to assign (e.g. 192.168.34.12/24)
    '''
    changedict = {}
    ret = {'name': name,
           'changes': changedict,
           'comment': ''}
    if __opts__['test']:
        ret['result'] = None
    else:
        ret['result'] = True
    try:
        # Check datalink IP stack
        if name not in __salt__['solaris_network.get_interfaces']():
            if not __opts__['test']:
                __salt__['solaris_network.set_datalink'](name, ipstack=True)
            changedict['new'] = {'IP stack': 'created'}
        # Check IP addr
        if ipaddr not in __salt__['solaris_network.get_addresses'](name):
            if not __opts__['test']:
                __salt__['solaris_network.set_interface'](name, cidr=ipaddr)
            if 'new' not in changedict:
                changedict['new'] = {}
            changedict['new']['IP address'] = ipaddr
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
    return ret


def ip_present(name):
    '''
    Ensure the IP stack exists on the specified datalink.

    :param str name: Datalink name
    '''
    changedict = {}
    ret = {'name': name,
           'changes': changedict,
           'comment': ''}
    if __opts__['test']:
        ret['result'] = None
    else:
        ret['result'] = True
    try:
        if name in __salt__['solaris_network.get_interfaces']():
            ret['comment'] = 'IP stack exists on datalink ('+name+')'
        else:
            if not __opts__['test']:
                __salt__['solaris_network.set_datalink'](name, ipstack=True)
            changedict['new'] = 'IP stack created'
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
    return ret


def ip_absent(name):
    '''
    Ensure the IP stack does not exist on the specified datalink.

    :param str name: Datalink name
    '''
    changedict = {}
    ret = {'name': name,
           'changes': changedict,
           'comment': ''}
    if __opts__['test']:
        ret['result'] = None
    else:
        ret['result'] = True
    try:
        if name in __salt__['solaris_network.get_interfaces']():
            if not __opts__['test']:
                __salt__['solaris_network.set_datalink'](name, ipstack=False)
            changedict['new'] = 'IP stack deleted'
        else:
            ret['comment'] = 'IP stack does not exist on datalink ('+name+')'
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
    return ret


def datalink_renamed(name, newname):
    '''
    Ensure the specified datalink is renamed

    :param str name: Datalink name
    :param str newname: New datalink name
    '''
    changedict = {'old': None, 'new': None}
    ret = {'name': name,
           'changes': changedict,
           'comment': ''}
    if __opts__['test']:
        ret['result'] = None
    else:
        ret['result'] = True
    try:
        links = __salt__['solaris_network.get_datalinks']()
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        ret['result'] = False
        return ret
    if newname not in links:
        if name not in links:
            ret['comment'] = 'Datalink '+name+' not found'
            ret['result'] = False
            return ret
        if not __opts__['test']:
            try:
                __salt__['solaris_network.set_datalink'](name, newname)
            except CommandExecutionError as err:
                ret['comment'] = str(err)
                ret['result'] = False
                return ret
        changedict['new'] = 'Renamed'
    else:
        changedict.clear()
    return ret
