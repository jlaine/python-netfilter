#!/usr/bin/env python

from setuptools import setup

setup(
    name='python-netfilter',
    version='0.6.1',
    description='Python modules for manipulating netfilter rules',
    url='https://github.com/jlaine/python-netfilter',
    author='Jeremy Laine',
    author_email='jeremy.laine@m4x.org',
    license='GPLv3+',
    packages=['netfilter'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
    ],
    test_suite='tests',
)
