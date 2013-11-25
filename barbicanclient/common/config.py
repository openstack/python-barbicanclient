# Copyright (c) 2013 Rackspace, Inc.
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

"""
Configuration setup for Barbican Client.
"""

import logging
import logging.config
import logging.handlers
import os
import sys

from barbicanclient.openstack.common.gettextutils import _
from barbicanclient.version import __version__
from oslo.config import cfg

CONF = cfg.CONF
CONF.import_opt('verbose', 'barbicanclient.openstack.common.log')
CONF.import_opt('debug', 'barbicanclient.openstack.common.log')
CONF.import_opt('log_dir', 'barbicanclient.openstack.common.log')
CONF.import_opt('log_file', 'barbicanclient.openstack.common.log')
CONF.import_opt('log_config', 'barbicanclient.openstack.common.log')
CONF.import_opt('log_format', 'barbicanclient.openstack.common.log')
CONF.import_opt('log_date_format', 'barbicanclient.openstack.common.log')
CONF.import_opt('use_syslog', 'barbicanclient.openstack.common.log')
CONF.import_opt('syslog_log_facility', 'barbicanclient.openstack.common.log')


def parse_args(args=None, usage=None, default_config_files=None):
    CONF(args=args,
         project='barbicanclient',
         prog='barbicanclient',
         version=__version__,
         usage=usage,
         default_config_files=default_config_files)
