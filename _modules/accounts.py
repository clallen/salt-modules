# -*- coding: utf-8 -*-
'''
Execution module for various account processes

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import
import logging
import re

# pylint: disable=too-many-statements,broad-except,too-many-nested-blocks


class Group:
    '''
    Parent class to contain data and processes common to all sudoers groups
    '''
    def __init__(self, line: str, group_tag: str, item_regex: str) -> None:
        self.item_regex = item_regex
        self.items = set()
        self.complete = False
        if not line.endswith('\\'):
            self.complete = True
        group_regex = r'{}\s+(\w+)\s*='.format(group_tag)
        str_line = line.replace('\t', ' ')
        match = re.match(group_regex, str_line, flags=re.ASCII)
        if match is None:
            msg = 'No match when parsing group name: {}'
            raise Exception(msg.format(str_line))
        self.name = match.group(1)
        items = self._parse_items(line)
        self.items.update(items)

    def _parse_items(self, line: str) -> list:
        str_line = line.replace('\t', ' ')
        regex = self.item_regex
        if '=' in str_line:
            regex = '='+self.item_regex
        match = re.search(regex, str_line, flags=re.ASCII)
        if match is None:
            msg = 'No match when parsing items: {}'
            raise Exception(msg.format(str_line))
        comma_sep = match.group(1).rstrip(',')
        parsed = comma_sep.split(',')
        return parsed

    def add_items(self, line: str) -> None:
        '''
        Parse the given line for items to add to this group
        '''
        items = self._parse_items(line)
        self.items.update(items)
        if not line.endswith('\\'):
            self.complete = True


class UserGroup(Group):
    '''
    Encapsulates a sudoers user group (User_Alias)
    '''
    def __init__(self, line: str) -> None:
        super().__init__(line, 'User_Alias', r'([\w,]+),*')
        self.host_groups = set()
        self.approver = ''


class HostGroup(Group):
    '''
    Encapsulates a sudoers host group (Host_Alias)
    '''
    def __init__(self, line: str) -> None:
        super().__init__(line, 'Host_Alias', r'([\w,\-]+),*')


def sudo_sox_parse(input_file, output_file):
    '''
    Parse a sudoers file for SOX-scoped entries.
    Output is written as a CSV file.

    :raises: OSError on file read/write errors
    :param str input_file: Full path to source sudoers file
    :param str output_file: Full path to output CSV file.
    File will be truncated if it exists.
    '''
    log = logging.getLogger(__name__)
    with open(input_file, encoding='utf-8') as fd:
        lines = fd.read()
    user_groups = {}
    host_groups = {}
    for line in lines.splitlines():
        if '# SUPERGROUP:' in line or '# PROJECT:' in line:
            parsing = False
            approver = ''
            continue
        if '# TAGS: SOX' in line:
            parsing = True
            continue
        if '# APPROVER:' in line:
            str_line = line.replace('\t', ' ')
            match = re.search(r'APPROVER:\s+([\w\.]+@[\w\.]+)', str_line,
                              flags=re.ASCII)
            if match is None:
                msg = 'No match when parsing approver: {}'.format(str_line)
                log.warning(msg)
            else:
                approver = match.group(1)
            continue
        if line.startswith('#'):
            continue
        if parsing:
            if line.startswith('User_Alias'):
                try:
                    cur_group = UserGroup(line)
                except Exception as err:
                    log.warning(err)
                else:
                    cur_group.approver = approver
                    user_groups[cur_group.name] = cur_group
            elif line.startswith('Host_Alias'):
                try:
                    cur_group = HostGroup(line)
                except Exception as err:
                    log.warning(err)
                else:
                    host_groups[cur_group.name] = cur_group
            elif user_groups:
                group_list = list(user_groups.values())
                cur_group = group_list[-1]
                if not cur_group.complete:
                    try:
                        cur_group.add_items(line)
                    except Exception as err:
                        log.warning(err)
            elif host_groups:
                group_list = list(host_groups.values())
                cur_group = group_list[-1]
                if not cur_group.complete:
                    try:
                        cur_group.add_items(line)
                    except Exception as err:
                        log.warning(err)
    # Expand nested user groups
    for user_group in user_groups.values():
        for item in list(user_group.items):
            if item.isupper():
                nested_group = user_groups[item]
                user_group.items.remove(item)
                user_group.items.update(nested_group.items)
    # Associate host groups with user groups
    for user_group in user_groups.values():
        for line in lines.splitlines():
            if '# SUPERGROUP:' in line or '# PROJECT:' in line:
                parsing = False
                continue
            if '# TAGS: SOX' in line:
                parsing = True
                continue
            if line.startswith('#'):
                continue
            if parsing:
                if line.startswith(user_group.name):
                    str_line = line.replace('\t', ' ')
                    match = re.search(r'\s+([\w,]+)\s*=', str_line,
                                      flags=re.ASCII)
                    if match is None:
                        msg = 'No match when parsing host group: %s'
                        log.warning(msg, str_line)
                        continue
                    group = match.group(1)
                    for name in group.split(','):
                        if name == 'ALL':
                            user_group.host_groups.add('ALL_SERVERS')
                        elif name not in host_groups:
                            user_group.host_groups.add(name)
                        else:
                            user_group.host_groups.add(host_groups[name])
    # Build output records
    index = 1
    fields = []
    records = ['"ID","Username","UserGroup","Entitlements","Approvers"\n']
    for group in user_groups.values():
        for host_group in group.host_groups:
            for user in group.items:
                fields.append('"{}"'.format(index))
                fields.append('"{}"'.format(user))
                fields.append('{}({})'.format(user, group.name))
                if isinstance(host_group, str):
                    fields.append('"{}"'.format(host_group))
                else:
                    hosts_str = ','.join(host_group.items)
                    fields.append('"{}={}"'.format(host_group.name, hosts_str))
                fields.append('"{}"'.format(group.approver))
                record = ','.join(fields)
                records.append('{}\n'.format(record))
                fields.clear()
                index += 1
    # Write output file
    with open(output_file, mode='w', encoding='utf-8') as fd:
        fd.writelines(records)
