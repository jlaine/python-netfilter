#!/usr/bin/env python

from distutils.core import setup

import netfilter

setup(name="python-netfilter",
      version=str(netfilter.__version__),
      license=netfilter.__license__,
      url=netfilter.__url__,
      packages=['netfilter'])
