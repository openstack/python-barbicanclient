#!/usr/bin/python
# -*- encoding: utf-8 -*-
# Copyright (c) 2013 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import setuptools


name = 'python-barbicanclient'


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def get_version():
    PKG = "barbicanclient"
    VERSIONFILE = os.path.join(PKG, "version.py")
    version = "unknown"
    try:
        version_file = open(VERSIONFILE, "r")
        for line in version_file:
            if '__version__' in line:
                version = line.split("'")[1]
                break
    except EnvironmentError:
        pass  # Okay, there is no version file.
    return version

setuptools.setup(
    name=name,
    version=get_version(),
    description='Client Library for OpenStack Barbican Key Management API',
    long_description=read('README.md'),
    keywords="openstack encryption key-management secret",
    url='https://github.com/cloudkeep/barbican',
    license='Apache License (2.0)',
    author='Rackspace, Inc.',
    author_email='openstack-dev@lists.openstack.org',
    packages=setuptools.find_packages(
        exclude=['tests', 'tests.*', 'examples', 'examples.*']
    ),
    install_requires=[
        'argparse>=1.2.1',
        'eventlet>=0.13.0',
        'requests>=1.2.3',
        'python-keystoneclient>=0.3.2',
    ],
    test_suite='nose.collector',
    tests_require=['nose'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: OpenStack',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Environment :: No Input/Output (Daemon)',
    ],
    entry_points="""
    [console_scripts]
    keep = barbicanclient.keep:main
    """
)
