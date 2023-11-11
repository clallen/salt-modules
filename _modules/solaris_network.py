# -*- coding: utf-8 -*-
'''
Execution module for configuring and querying Solaris network components

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import
import logging

from salt.exceptions import CommandExecutionError

HOSTSFILE = '/etc/inet/hosts'
IPADM = '/usr/sbin/ipadm'
DLADM = '/usr/sbin/dladm'
LLDPADM = '/usr/sbin/lldpadm'
SVCCFG = '/usr/sbin/svccfg'
SVCADM = '/usr/sbin/svcadm'
ROUTE = '/usr/sbin/route'


def __virtual__():
    '''
    Only run on Solaris 11 or up
    '''
    if all([__grains__['kernel'] == 'SunOS',
            __grains__['kernelrelease'] == '5.11']):
        return True
    return False, 'This module must be run on Solaris 11 or up.'


def ipmp_create(ifname, links, cidr=None):
    '''
    Create an IPMP interface, optionally assigning a static IPv4 address
    (a corresponding IPv6 address will also be assigned).

    :param str ifname: IPMP interface name
    :param list links: The datalinks to be used
    :param str cidr: IPv4 CIDR address to assign (e.g. 192.168.34.12/24).
    If None, no address is assigned
    :raises: CommandExecutionError: Problem running a shell command
    '''
    # Setup links
    for link in links:
        ret = __salt__['cmd.run_all'](DLADM+
                                      ' show-linkprop -co VALUE -p state '+
                                      link, output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error getting datalink state for '+
                                        link, info=ret['stderr'])
        if ret['stdout'] != 'up':
            ret = __salt__['cmd.run_all'](IPADM+' create-ip '+link,
                                          output_loglevel='quiet')
            if ret['retcode'] and 'exists' not in ret['stderr']:
                raise CommandExecutionError('Error creating IP on '+link,
                                            info=ret['stderr'])
    # Create ipmp
    ret = __salt__['cmd.run_all'](IPADM+' create-ipmp -i '+','.join(links)+
                                  ' '+ifname, output_loglevel='quiet')
    if ret['retcode'] and 'exists' not in ret['stderr']:
        raise CommandExecutionError('Error creating IPMP interface '+ifname,
                                    info=ret['stderr'])
    # Optional IP
    if cidr is not None:
        set_interface(ifname, cidr=cidr)


def ipmp_add(ifname, links):
    '''
    Add datalinks to an IPMP group.

    :param str ifname: IPMP group name
    :param list links: Links to add
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](IPADM+' add-ipmp -i '+','.join(links)+
                                  ' '+ifname, output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error adding links to IPMP interface '+
                                    ifname, info=ret['stderr'])


def ipmp_trans_probe(state):
    '''
    Enable or disable IPMP transitive probing.

    :param bool state: True for enabled, False for disabled
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](SVCCFG+' -s ipmp:default setprop config/'+
                                  'transitive-probing = boolean: '+
                                  str(state).lower(), output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error setting transitive probing ('+
                                    +state+')', info=ret['stderr'])
    ret = __salt__['cmd.run_all'](SVCADM+' refresh ipmp:default',
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error refreshing ipmp service',
                                    info=ret['stderr'])


def ipmp_get_datalinks(ifname):
    '''
    Get member datalinks in the given IPMP group.

    :param str ifname: IPMP interface name
    :rtype: list
    :returns: Datalinks in the IPMP group
    :raises: CommandExecutionError: Problem running a shell command
    :raises: ValueError: Non-IPMP interface given
    '''
    # Check interface class
    ret = __salt__['cmd.run_all'](IPADM+' show-if -p -o CLASS '+ifname)
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error getting class on interface: '+ifname,
                                    info=ret['stderr'])
    if ret['stdout'] != 'ipmp':
        raise ValueError('Interface ('+ifname+') has invalid type: ('+
                         ret['stdout']+')')
    # Get datalinks
    ret = __salt__['cmd.run_all'](IPADM+' show-if -p -o OVER '+ifname)
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying IPMP interface '+ifname,
                                    info=ret['stderr'])
    return ret['stdout'].split()


def aggr_create(aggrname, links, lacpmode='active', lacptimer='short'):
    '''
    Create a link aggregation.

    :param str aggrname: Aggregation link name
    :param list links: The datalinks to be used
    :param str lacpmode: LACP mode, one of: off, active, passive
    :param str lacptimer: LACP timer value, one of: short, long
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](DLADM+' create-aggr -L '+lacpmode+' -T '+
                                  lacptimer+' -l '+' -l '.join(links)+' '+
                                  aggrname, output_loglevel='quiet')
    if ret['retcode'] and 'exists' not in ret['stderr']:
        raise CommandExecutionError('Error creating aggr link '+aggrname,
                                    info=ret['stderr'])


def set_datalink(linkname, newname=None, lldp_mode=None, ipstack=None):
    '''
    Set various properties of a datalink.

    :param str linkname: Current link name
    :param str newname: Set new link name
    :param str lldp_mode: Set LLDP mode (see lldpadm(1M))
    :param bool ipstack: If True, create IP stack, if False delete it
    :raises: CommandExecutionError: Problem running a shell command
    '''
    if newname is not None:
        ret = __salt__['cmd.run_all'](DLADM+' rename-link '+linkname+' '+
                                      newname, output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error renaming datalink from '+
                                        linkname+' to '+newname,
                                        info=ret['stderr'])
    if lldp_mode is not None:
        ret = __salt__['cmd.run_all'](LLDPADM+' set-agentprop -p mode='+
                                      lldp_mode+' '+linkname,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error setting LLDP to '+lldp_mode+
                                        ' on link '+linkname,
                                        info=ret['stderr'])
    if ipstack is not None:
        if ipstack:
            ret = __salt__['cmd.run_all'](IPADM+' create-ip '+linkname,
                                          output_loglevel='quiet')
            if ret['retcode'] and 'exists' not in ret['stderr']:
                raise CommandExecutionError('Error creating IP stack'+
                                            ' on link '+linkname,
                                            info=ret['stderr'])
        else:
            ret = __salt__['cmd.run_all'](IPADM+' delete-ip '+linkname,
                                          output_loglevel='quiet')
            if ret['retcode'] != 0:
                raise CommandExecutionError('Error deleting IP stack'+
                                            ' on link '+linkname,
                                            info=ret['stderr'])


def set_interface(ifname, cidr=None, ipv6=True):
    '''
    Set various properties of an interface.

    :param str ifname: Interface name
    :param str cidr: IPv4 CIDR address to assign (e.g. 192.168.34.12/24).
    A hostname may also be used.
    If string is empty, delete address.
    :param bool ipv6: If True, use addrconf to create a matching IPv6 address
    :raises: CommandExecutionError: Problem running a shell command
    '''
    if cidr is not None:
        if cidr:
            ret = __salt__['cmd.run_all'](IPADM+
                                          ' create-addr -a local='+
                                          cidr+' '+ifname,
                                          output_loglevel='quiet')
            if ret['retcode'] and 'exists' not in ret['stderr']:
                raise CommandExecutionError('Error creating IPv4 address'+
                                            ' on interface '+ifname,
                                            info=ret['stderr'])
            if ipv6:
                ret = __salt__['cmd.run_all'](IPADM+' create-addr -T addrconf '+
                                              ifname, output_loglevel='quiet')
                if ret['retcode'] and 'exists' not in ret['stderr']:
                    raise CommandExecutionError('Error creating IPv6 address'+
                                                ' on interface '+ifname,
                                                info=ret['stderr'])
        else:
            ret = __salt__['cmd.run_all'](IPADM+' delete-addr '+ifname,
                                          output_loglevel='quiet')
            if ret['retcode'] != 0:
                raise CommandExecutionError('Error deleting IP address'+
                                            ' on interface '+ifname,
                                            info=ret['stderr'])


def set_dns(nameservers=None, search=None):
    '''
    Set DNS configuration properties in SMF.

    :param list nameservers: IPv4 addresses for new nameservers, these will
    replace existing ones.  If None, nameservers will not be changed.
    :param list search: DNS search domains, these will replace existing ones.
    If None, search domains will not be changed.
    :raises: CommandExecutionError: Problem running a shell command
    '''
    log = logging.getLogger(__name__)
    changed = False
    if nameservers is not None:
        # 11.3 requires all strings to be double-quoted, 11.4 does not
        osrelease_info = __salt__['grains.get']('osrelease_info')
        if osrelease_info[1] == 3:
            ns_str = '\'("{0}")\''.format('" "'.join(nameservers))
        else:
            ns_str = '\\({0}\\)'.format(' '.join(nameservers))
        log.debug('ns_str: %s', ns_str)
        ret = __salt__['cmd.run_all'](SVCCFG+' -s svc:/network/dns/client '
                                      'setprop config/nameserver = '
                                      'net_address: '+ns_str,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error setting DNS nameservers',
                                        info=ret['stderr'])
        changed = True
    if search is not None:
        # 11.3 requires all strings to be double-quoted, 11.4 does not
        osrelease_info = __salt__['grains.get']('osrelease_info')
        if osrelease_info[1] == 3:
            search_str = '\'("{0}")\''.format('" "'.join(search))
        else:
            search_str = '\'({0})\''.format(' '.join(search))
        log.debug('search_str: %s', search_str)
        ret = __salt__['cmd.run_all'](SVCCFG+' -s svc:/network/dns/client '
                                      'setprop config/search = astring: '+
                                      search_str,
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error setting DNS search domains',
                                        info=ret['stderr'])
        changed = True
    if changed:
        ret = __salt__['cmd.run_all'](SVCADM+' refresh svc:/network/dns/client',
                                      output_loglevel='quiet')
        if ret['retcode'] != 0:
            raise CommandExecutionError('Error refreshing DNS client service',
                                        info=ret['stderr'])


def set_default_route(gateway):
    '''
    Set the default route, replacing the existing one.

    :param str gateway: IPv4 gateway address
    :raises: CommandExecutionError: Problem running a shell command
    '''
    # Get current gateway
    ret = __salt__['cmd.run_all'](ROUTE+' -p show', output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error getting current default gateway '+
                                    gateway, info=ret['stderr'])
    old_gateway = ret['stdout'].split().pop()
    if old_gateway == gateway:
        return
    # Set new gateway
    ret = __salt__['cmd.run_all'](ROUTE+' -p add default '+gateway,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error adding default gateway '+gateway,
                                    info=ret['stderr'])
    # Delete old gateway
    ret = __salt__['cmd.run_all'](ROUTE+' -p delete default '+old_gateway,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error removing old default gateway '+
                                    old_gateway, info=ret['stderr'])


def set_hostname(newname, ipaddr=None):
    '''
    Set the hostname, which includes the SMF identity nodename property,
    /etc/inet/hosts, and /etc/passwd.
    If *newname* and the existing hostname are the same, only /etc/inet/hosts is
    updated, with the new IP address.

    :param str newname: New hostname, can be same as existing name if only the
    IP is changing
    :param str ipaddr: IPv4 address of new hostname.  If None a DNS lookup will
    be attempted.
    :raises: LookupError: DNS lookup for *newname* failed
    :raises: CommandExecutionError: Problem running a shell command
    '''
    oldname = __grains__['id']
    # Replace hosts entry
    if ipaddr is None:
        pattern = r'\b{0}\b'.format(oldname)
        repl = newname
    else:
        dns_domain = __salt__['pillar.get']('net:dns_domain')
        pattern = r'^.*\b{0}\b.*$'.format(oldname)
        repl = ipaddr+' '+newname+' '+newname+'.'+dns_domain
    __salt__['file.replace'](HOSTSFILE, pattern, repl, backup=False)
    # Replace name in passwd
    __salt__['file.replace']('/etc/passwd', oldname, newname, backup=False)
    # Update SMF identity nodename
    ret = __salt__['cmd.run_all'](SVCCFG+' -s identity:node setprop '+
                                  'config/nodename = astring: '+newname,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error setting identity nodename property '+
                                    'for new hostname '+newname,
                                    info=ret['stderr'])
    ret = __salt__['cmd.run_all'](SVCADM+' refresh identity:node',
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error refreshing identity:node',
                                    info=ret['stderr'])


def get_datalinks():
    '''
    Get the system's datalink names.

    :rtype: list
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](DLADM+' show-link -p -o LINK',
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying datalinks',
                                    info=ret['stderr'])
    return ret['stdout'].splitlines()


def get_interfaces():
    '''
    Get the system's network interface names.

    :rtype: list
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](IPADM+' show-if -p -o IFNAME',
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying interfaces',
                                    info=ret['stderr'])
    return ret['stdout'].split('\n')


def get_addresses(ifname):
    '''
    Get IP addresses associated with the specified interface.

    :param str ifname: Interface name
    :rtype: list
    :raises: CommandExecutionError: Problem running a shell command
    '''
    ret = __salt__['cmd.run_all'](IPADM+' show-addr -p -o ADDR '+ifname,
                                  output_loglevel='quiet')
    if ret['retcode'] != 0:
        raise CommandExecutionError('Error querying addresses for interface '+
                                    ifname, info=ret['stderr'])
    return ret['stdout'].split('\n')
