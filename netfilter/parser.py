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

import re
try:
    from UserDict import UserDict
except ImportError:
    from collections import UserDict

import netfilter.rule

# define useful regexps
re_chain = re.compile(r'^:*([^\s]+) ([^\s]+) \[([0-9]+):([0-9]+)\]$')
re_rule = re.compile(r'^\[([0-9]+):([0-9]+)\] -A ([^\s]+) (.*)$')
re_word = re.compile(r'("[^"]*"|[^\s]+)')
re_main_opt = re.compile(r'^-([^-])$')

class odict(UserDict):
    def __init__(self, dict = None):
        self._keys = []
        UserDict.__init__(self, dict)

    def __setitem__(self, key, item):
        UserDict.__setitem__(self, key, item)
        if key not in self._keys: self._keys.append(key)

    def keys(self):
        return self._keys
    
class ParseError(Exception):
    pass

def split_words(line):
    def unquote(x):
        if x and x[0] == '"':
            return x[1:-1]
        else:
            return x

    if '"' in line:
        # handle quoted arguments
        return [ unquote(x) for x in re_word.findall(line) ]
    else:
        # shortcut for the bulk of cases
        return line.split()

def pull_extension_opts(bits, pos):
    opt_bits = []
    while pos < len(bits) and not re_main_opt.match(bits[pos]):
        opt_bits.append(bits[pos])
        pos += 1
    return opt_bits, pos

def pull_main_opt(bits, pos):
    val = bits[pos]
    pos += 1
    if val == '!':
        val += ' ' + bits[pos]
        pos += 1
    return val, pos

def parse_rule(spec):
    rule = netfilter.rule.Rule()
    bits = split_words(spec)
    pos = 0
    while pos < len(bits):
        # in iptables 1.4.3, negation moved before the match option
        if bits[pos] == '!' and pos < len(bits) - 1:
            bits[pos] = bits[pos+1]
            bits[pos+1] = '!'
        bit = bits[pos]
        pos += 1
        if bit == '-d':
            rule.destination, pos = pull_main_opt(bits, pos)
        elif bit == '-i':
            rule.in_interface, pos = pull_main_opt(bits, pos)
        elif bit == '-g':
            target_name = bits[pos]
            opts, pos = pull_extension_opts(bits, pos + 1)
            rule.goto = netfilter.rule.Target(target_name, opts)
        elif bit == '-j':
            target_name = bits[pos]
            opts, pos = pull_extension_opts(bits, pos + 1)
            rule.jump = netfilter.rule.Target(target_name, opts)
        elif bit == '-m':
            match_name = bits[pos]
            opts, pos = pull_extension_opts(bits, pos + 1) 
            rule.matches.append(
                netfilter.rule.Match(match_name, opts))
        elif bit == '-o':
            rule.out_interface, pos = pull_main_opt(bits, pos)
        elif bit == '-p':
            rule.protocol, pos = pull_main_opt(bits, pos)
        elif bit == '-s':
            rule.source, pos = pull_main_opt(bits, pos)
        else:
            raise ParseError("unhandled option '%s' in rule '%s'" % (bit, spec))
    return rule

def parse_chains(data):
    """
    Parse the chain definitions.
    """
    chains = odict()
    for line in data.splitlines(True):
        m = re_chain.match(line)
        if m:
            policy = None
            if m.group(2) != '-':
                policy = m.group(2)
            chains[m.group(1)] = {
                'policy': policy,
                'packets': int(m.group(3)),
                'bytes': int(m.group(4)),
            }
    return chains

def parse_rules(data, chain):
    """
    Parse the rules for the specified chain.
    """
    rules = []
    for line in data.splitlines(True):
        m = re_rule.match(line)
        if m and m.group(3) == chain:
            rule = parse_rule(m.group(4))
            rule.packets = int(m.group(1))
            rule.bytes = int(m.group(2))
            rules.append(rule)
    return rules
