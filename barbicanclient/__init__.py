#   Copyright 2017 Huawei, Inc. All rights reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

"""Barbican Client Library Binding"""

import importlib
import sys
import warnings

import pbr.version

from barbicanclient.v1 import acls
from barbicanclient.v1 import cas
from barbicanclient.v1 import containers
from barbicanclient.v1 import orders
from barbicanclient.v1 import secrets


version_info = pbr.version.VersionInfo("python-barbicanclient")
__version__ = version_info.version_string()

__all__ = (
    'acls',
    'cas',
    'containers',
    'orders',
    'secrets',
)


class _LazyImporter(object):
    def __init__(self, module):
        self._module = module

    def __getattr__(self, name):
        # This is only called until the import has been done.
        lazy_submodules = [
            'acls',
            'cas',
            'containers',
            'orders',
            'secrets',
        ]
        if name in lazy_submodules:
            warnings.warn("The %s module is moved to barbicanclient/v1 "
                          "directory, direct import of barbicanclient.%s "
                          "will be deprecated. Please import "
                          "barbicanclient.v1.%s instead."
                          % (name, name, name))
            return importlib.import_module('barbicanclient.v1.%s' % name)

        # Return module attributes like __all__ etc.
        return getattr(self._module, name)


sys.modules[__name__] = _LazyImporter(sys.modules[__name__])
