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
import subprocess
import sys

from netfilter.rule import Rule,Match,Target
import netfilter.table

class Firewall:
    """The Firewall class represents a simple netfilter-based firewall.
    It support 'start', 'stop' and 'restart' operations.

    WARNING: THIS API IS NOT FROZEN!
    """
    def __init__(self, auto_commit = True, ipv6 = False):
        self.filter = netfilter.table.Table(
            name='filter',
            auto_commit=auto_commit,
            ipv6=ipv6)
        self.__ipv6 = ipv6
        self.__tables = [ self.filter ]
        if not ipv6:
            self.nat = netfilter.table.Table(
                name='nat',
                auto_commit=auto_commit,
                ipv6=ipv6)
            self.__tables.append(self.nat)
     
    def clear(self):
        """Clear tables."""
        for table in self.__tables: 
            table.flush_chain()
            table.delete_chain()
       
    def commit(self):
        """Commit changes to the tables."""
        for table in self.__tables: 
            table.commit()
    
    def get_buffer(self):
        """Get the change buffers."""
        buffer = []
        for table in self.__tables: 
            buffer.extend(table.get_buffer())
        return buffer
    
    def run(self, args):
        """
        Process command line arguments and run the given command command
        (start, stop, restart).
        """
        prog = args[0]
        if len(args) < 2:
            self.usage(prog)
            return 1

        command = args[1]
        if command == "start":
            self.start()
        elif command == "stop":
            self.stop()
        elif command == "restart":
            self.stop()
            self.start()
        else:
            self.usage(prog)
            return 1
        return 0
    
    def start(self):
        """Start the firewall."""
        self.clear()
        self.setDefaultPolicy()
        self.acceptIcmp()
        self.acceptInput('lo')
    
    def stop(self):
        """Stop the firewall."""
        self.clear()
        self.setOpenPolicy()
    
    def usage(self, prog):
        """Print program usage."""
        sys.stderr.write("Usage: %s {start|stop|restart}\n" % prog)

    def acceptForward(self, in_interface=None, out_interface=None):
        self.printMessage("allow FORWARD", in_interface)
        self.filter.append_rule('FORWARD', Rule(
            in_interface=in_interface,
            out_interface=out_interface,
            jump='ACCEPT'))

    def acceptIcmp(self, interface=None):
        self.printMessage("allow selected icmp INPUT", interface)
        if self.__ipv6:
            self.filter.append_rule('INPUT', Rule(
                in_interface=interface,
                protocol='icmpv6',
                jump='ACCEPT'))
        else:
            types = ['echo-request',
                'network-unreachable',
                'host-unreachable',
                'port-unreachable',
                'fragmentation-needed',
                'time-exceeded']

            for type in types:
                self.filter.append_rule('INPUT', Rule(
                    in_interface=interface,
                    protocol='icmp',
                    matches=[Match('icmp', "--icmp-type %s" % (type))],
                    jump='ACCEPT'))

    def acceptInput(self, interface=None):
        self.printMessage("allow INPUT", interface)
        self.filter.append_rule('INPUT', Rule(
            in_interface=interface,
            jump='ACCEPT'))

    def acceptProtocol(self, interface, protocol, ports, destination=None, source=None):
        port_str = ','.join(ports)
        self.printMessage("allow selected %s INPUT (ports: %s)" % (protocol, port_str), interface)
        self.filter.append_rule('INPUT', Rule(
            in_interface=interface,
            destination=destination,
            source=source,
            protocol=protocol,
            matches=[Match('state', '--state NEW'),
                Match('multiport', "--destination-port %s" % port_str)],
            jump='ACCEPT'))

    def getNode(self):
        p = subprocess.Popen(["uname", "-n"],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            close_fds=True)
        out, err = p.communicate()
        status = p.wait()
        # check exit status
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            raise Exception("uname failed : %s" % ''.join(err))
        node = out.strip()
        return node

    def printMessage(self, msg, interface=None):
        if self.__ipv6:
            version = 'IPv6'
        else:
            version = 'IPv4'
        if interface:
            prefix = "interface %s" % interface
        else:
            prefix = "global"
        sys.stderr.write(" * %s %s: %s\n" % (version, prefix, msg))

    def redirectHttp(self, interface, proxy_port):
        if self.__ipv6: return
        self.printMessage("redirect HTTP to port %s" % proxy_port, interface)
        self.nat.append_rule('PREROUTING', Rule(
            in_interface=interface,
            protocol='tcp',
            matches=[Match('tcp', '--dport 80')],
            jump=Target('REDIRECT', '--to-port %s' % proxy_port)))
    
    def setDefaultPolicy(self):
        self.printMessage("set default policy", None)
        self.filter.set_policy('INPUT', 'DROP')
        self.filter.append_rule('INPUT', Rule(
            matches=[Match('state', '--state ESTABLISHED,RELATED')],
            jump='ACCEPT'))
        self.filter.set_policy('OUTPUT', 'ACCEPT')
        self.filter.set_policy('FORWARD', 'DROP')
        self.filter.append_rule('FORWARD', Rule(
            matches=[Match('state', '--state ESTABLISHED,RELATED')],
            jump='ACCEPT'))
    
    def setOpenPolicy(self):
        self.printMessage("set open policy", None)
        self.filter.set_policy('INPUT', 'ACCEPT')
        self.filter.set_policy('OUTPUT', 'ACCEPT')
        self.filter.set_policy('FORWARD', 'ACCEPT')
    
    def sourceNAT(self, interface):
        if self.__ipv6: return
        self.printMessage("enable SNAT", interface)
        self.nat.append_rule('POSTROUTING', Rule(
            out_interface=interface,
            jump='MASQUERADE'))

if __name__ == "__main__":
    sys.exit(Firewall().run(sys.argv))
