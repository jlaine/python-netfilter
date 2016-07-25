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

import logging
import re

import netfilter.parser

# define useful regexps
re_extension_opt = re.compile(r'^--(.*)$')

class Extension:
    """The Extension class is the base class for iptables match and target
    extensions.
    """
    def __init__(self, name, options, rewrite_options = {}):
        self.__name = name
        self.__options = {}
        self.__rewrite_options = rewrite_options
        if options:
            self.__parse_options(options)

    def __eq__(self, other):
        if isinstance(other, Extension):
            return self.__name == other.__name and \
                self.__options == other.__options
        else:
            return NotImplemented
    
    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __parse_options(self, options):
        if isinstance(options, list):
            bits = options
        else:
            bits = netfilter.parser.split_words(options)
        
        pos = 0
        cur_opt = []
        while pos < len(bits):
            if bits[pos] == '!':
                cur_opt.append(bits[pos])
                pos += 1
                continue
            
            # get option name
            m = re_extension_opt.match(bits[pos])
            if not m:
                raise Exception("expected option, got: %s" % bits[pos])
            pos += 1
            # rewrite option to its canonical name
            tmp_opt = m.group(1)
            if tmp_opt in self.__rewrite_options:
                tmp_opt = self.__rewrite_options[tmp_opt]
            cur_opt.append(tmp_opt)
            
            # collect value(s)
            vals = []
            while pos < len(bits) and not re_extension_opt.match(bits[pos]):
                vals.append(bits[pos])
                pos += 1
            
            # store option
            opt = ' '.join(cur_opt)
            self.__options[opt] = vals
            
            # reset current option name
            cur_opt = []

    def log(self, level, prefix = ''):
        """Writes the contents of the Extension to the logging system.
        """
        logging.log(level, "%sname: %s", prefix, self.__name)
        logging.log(level, "%soptions: %s", prefix, self.__options)
    
    def name(self):
        """Accessor for the Extension's name.
        """
        return self.__name
    
    def options(self):
        """Accessor for the Extension's options.
        """
        return self.__options
    
    def specbits(self):
        """Returns the array of arguments that would be given to
        iptables for the current Extension.
        """
        bits = []
        for opt in sorted(self.__options):
            # handle the case where this is a negated option
            m = re.match(r'^! (.*)', opt)
            if m:
                bits.extend(['!', "--%s" % m.group(1)])
            else:
                bits.append("--%s" % opt)
                
            optval = self.__options[opt]
            if isinstance(optval, list):
                bits.extend(optval)
            else:
                bits.append(optval)
        return bits

class Match(Extension):
    """The Match class represents an iptables match extension, for
    instance 'multiport'.
    """
    def __init__(self, name, options = None):
        Extension.__init__(self, name, options, {
            'destination-port': 'dport',
            'destination-ports': 'dports',
            'source-port': 'sport',
            'source-ports': 'sports'})
    
class Target(Extension):
    """The Target class represents an iptables target, which can be
    used in the 'jump' statement of a rule.
    """
    def __init__(self, name, options = None):
        Extension.__init__(self, name, options)
    
class Rule:
    """The Rule represents an iptables rule.
    """
    def __init__(self, **kwargs):
        # initialise rule definition
        self.protocol = None
        self.destination = None
        self.source = None
        self.goto = None
        self.jump = None
        self.in_interface = None
        self.out_interface = None
        self.matches = []
        # initialise counters
        self.packets = 0
        self.bytes = 0
        # assign supplied arguments
        for k, v in kwargs.items():
            self.__setattr__(k, v)
    
    def __eq__(self, other):
        if isinstance(other, Rule):
            return other.protocol == self.protocol and \
               other.in_interface == self.in_interface and \
               other.out_interface == self.out_interface and \
               other.source == self.source and \
               other.destination == self.destination and \
               other.goto == self.goto and \
               other.jump == self.jump and \
               other.matches == self.matches
        else:
            return NotImplemented
    
    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __setattr__(self, name, value):
        if name == 'source' or name == 'destination':
            # produce "canonical" form of a source / destination
            # FIXME: we need to handle arbitrary netmasks here
            if value is not None and value.endswith('/32'):
                value = value[:-3] 
        elif name == 'goto' or name == 'jump': 
            if value is not None and not isinstance(value, Target):
                value = Target(value)
        elif name == 'matches':
            if not isinstance(value, list):
                raise Exception("matches attribute requires a list")
        self.__dict__[name] = value

    def find(self, rules):
        """Convenience method that finds the current Rule in a list.
        """
        for rule in rules:
            if self == rule:
                return rule
        return None

    def log(self, level, prefix = ''):
        """Writes the contents of the Rule to the logging system.
        """
        logging.log(level, "%sin interface: %s", prefix, self.in_interface)
        logging.log(level, "%sout interface: %s", prefix, self.out_interface)
        logging.log(level, "%ssource: %s", prefix, self.source)
        logging.log(level, "%sdestination: %s", prefix, self.destination)
        logging.log(level, "%smatches:", prefix)
        for match in self.matches:
            match.log(level, prefix + '  ')
        if self.jump:
            logging.log(level, "%sjump:", prefix)
            self.jump.log(level, prefix + '  ')

    def specbits(self):
        """Returns the array of arguments that would be given to
        iptables for the current Rule.
        """
        def host_bits(opt, optval):
            # handle the case where this is a negated value
            m = re.match(r'^!\s*(.*)', optval)
            if m:
                return ['!', opt, m.group(1)]
            else:
                return [opt, optval]

        bits = []
        if self.protocol:
            bits.extend(host_bits('-p', self.protocol))
        if self.in_interface:
            bits.extend(host_bits('-i', self.in_interface))
        if self.out_interface:
            bits.extend(host_bits('-o', self.out_interface))
        if self.source:
            bits.extend(host_bits('-s', self.source))
        if self.destination:
            bits.extend(host_bits('-d', self.destination))
        for mod in self.matches:
            bits.extend(['-m', mod.name()])
            bits.extend(mod.specbits())
        if self.goto:
            bits.extend(['-g', self.goto.name()])
            bits.extend(self.goto.specbits())
        elif self.jump:
            bits.extend(['-j', self.jump.name()])
            bits.extend(self.jump.specbits())
        return bits

