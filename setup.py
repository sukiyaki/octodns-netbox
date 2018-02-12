#!/usr/bin/env python

from os.path import dirname, join
import octodns_netbox

try:
    from setuptools import find_packages, setup
except ImportError:
    from distutils.core import find_packages, setup

setup(
    author='Masaki Tagawa',
    author_email='masaki@sukiyaki.ski',
    description=octodns_netbox.__doc__,
    install_require=[
        'octodns>=0.8.0',
        'requests>=2.13.0',
        'fqdn>=1.1.0'
    ],
    tests_require=[
        'mock',
        'nose',
    ],
    test_suite='nose.collector',
    license='MIT',
    long_description=open('README.md').read(),
    name='octodns-netbox',
    packages=find_packages(),
    url='https://github.com/sukiyaki/octodns-netbox',
    version=octodns_netbox.__VERSION__,
)
