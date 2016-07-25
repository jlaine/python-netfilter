python-netfilter - Python modules for manipulating netfilter rules  
Copyright (C) 2007-2012 Bolloré Telecom  
Copyright (C) 2013-2016 Jeremy Lainé

About
=====

python-netfilter is a set of modules for the Python programming language which
allows you to manipulate netfilter rules.

License
=======

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Simple example
==============

    from netfilter.rule import Rule,Match
    from netfilter.table import Table

    rule = Rule(
        in_interface='eth0',
        protocol='tcp',
        matches=[Match('tcp', '--dport 80')],
        jump='ACCEPT')))

      table = Table('filter')
      table.append_rule('INPUT', rule)

      table.delete_rule('INPUT', rule)
