#!/usr/bin/env python

from setuptools import setup

setup(
    name='netfilter',
    version='0.6.3',
    description='Python modules for manipulating netfilter rules',
    url='https://github.com/jlaine/python-netfilter',
    author='Jeremy Laine',
    author_email='jeremy.laine@m4x.org',
    license='GPLv3+',
    packages=['netfilter'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Networking :: Firewalls',
        'Topic :: System :: Systems Administration',
    ],
    test_suite='tests',
)
