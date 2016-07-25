# -*- coding: utf-8 -*-
#
# python-netfilter - Python modules for manipulating netfilter rules
# Copyright (C) 2007-2012 Bolloré Telecom
# Copyright (C) 2013-2016 Jeremy Lainé
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import re
import subprocess

import netfilter.parser


class IptablesError(Exception):
    def __init__(self, command, message):
        self.command = command
        self.message = message
    
    def __str__(self):
        return "command: %s\nmessage: %s" % (self.command, self.message) 

class Table:
    """The Table class represents a netfilter table (IPv4 or IPv6).
    """

    __iptables_wait_option = None

    def __init__(self, name, auto_commit = True, ipv6 = False):
        """Constructs a new netfilter Table.
        
        If auto_commit is true, commands are executed immediately,
        otherwise they are buffered and you need to call the commit()
        method to execute them.

        If ipv6 is true then ip6tables and ip6tables-save are used
        instead of iptables and iptables-save.
        """
        self.auto_commit = auto_commit
        self.__name = name
        self.__buffer = []
        if ipv6:
            self.__iptables = 'ip6tables'
            self.__iptables_save = 'ip6tables-save'
        else:
            self.__iptables = 'iptables'
            self.__iptables_save = 'iptables-save'

    def create_chain(self, chainname):
        """Creates the specified user-defined chain.
        """
        self.__run_iptables(['-N', chainname])

    def delete_chain(self, chainname=None):
        """Attempts to delete the specified user-defined chain (all the
        chains in the table if none is given).
        """
        args = ['-X']
        if chainname: args.append(chainname)
        self.__run_iptables(args)

    def flush_chain(self, chainname=None):
        """Flushes the specified chain (all the chains in the table if
        none is given). This is equivalent to deleting all the rules
        one by one.
        """
        args = ['-F']
        if chainname: args.append(chainname)
        self.__run_iptables(args)
    
    def list_chains(self):
        """Returns a list of strings representing the chains in the 
        Table.
        """
        return self.__get_chains().keys()

    def rename_chain(self, old_chain_name, new_chain_name):
        """Renames the specified user-defined chain.
        """
        self.__run_iptables(['-E', old_chain_name, new_chain_name])

    def get_policy(self, chainname):
        """Gets the policy for the specified built-in chain.
        """
        return self.__get_chains()[chainname]['policy']
    
    def set_policy(self, chainname, policy):
        """Sets the policy for the specified built-in chain.
        """
        self.__run_iptables(['-P', chainname, policy])
    
    def append_rule(self, chainname, rule):
        """Appends a Rule to the specified chain.
        """
        self.__run_iptables(['-A', chainname] + rule.specbits())

    def delete_rule(self, chainname, rule):
        """Deletes a Rule from the specified chain.
        """
        self.__run_iptables(['-D', chainname] + rule.specbits())
    
    def prepend_rule(self, chainname, rule):
        """Prepends a Rule to the specified chain.
        """
        self.__run_iptables(['-I', chainname, '1'] + rule.specbits())

    def list_rules(self, chainname):
        """Returns a list of Rules in the specified chain.
        """
        data = self.__run([self.__iptables_save, '-t', self.__name, '-c'])
        return netfilter.parser.parse_rules(data, chainname)

    def commit(self):
        """Commits any buffered commands. This is only useful if
        auto_commit is False.
        """
        while len(self.__buffer) > 0:
            self.__run(self.__buffer.pop(0))
    
    def get_buffer(self):
        """Returns the command buffer. This is only useful if
        auto_commit is False.
        """
        return self.__buffer
    
    def __get_chains(self):
        data = self.__run([self.__iptables_save, '-t', self.__name, '-c'])
        return netfilter.parser.parse_chains(data)
    
    def __run_iptables(self, args):
        if Table.__iptables_wait_option is None:
            # check whether iptables supports --wait
            try:
                self.__run([self.__iptables, '-L', '-n', '--wait'])
                Table.__iptables_wait_option = ['--wait']
            except:
                Table.__iptables_wait_option = []

        cmd = [self.__iptables] + Table.__iptables_wait_option + ['-t', self.__name] + args
        if self.auto_commit:
            self.__run(cmd)
        else:
            self.__buffer.append(cmd)
    
    def __run(self, cmd):
        p = subprocess.Popen(cmd,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            close_fds=True)
        out, err = p.communicate()
        out = out.decode('utf8')
        err = err.decode('utf8')
        status = p.wait()
        # check exit status
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            if not re.match(r'(iptables|ip6tables): Chain already exists', err):
                raise IptablesError(cmd, err)
        return out

