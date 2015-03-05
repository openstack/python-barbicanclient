"""
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import os

from oslo.config import cfg
from tempest import config

CONF = config.CONF

# Use local tempest conf if one is available.
# This usually means we're running tests outside of devstack
if os.path.exists('./etc/functional_tests.conf'):
    CONF.set_config_path('./etc/functional_tests.conf')

CONF.register_group(cfg.OptGroup('keymanager'))
CONF.register_opt(cfg.StrOpt('url'), group='keymanager')
CONF.register_opt(cfg.StrOpt('username'), group='keymanager')
CONF.register_opt(cfg.StrOpt('password'), group='keymanager')
CONF.register_opt(cfg.StrOpt('project_name'), group='keymanager')
CONF.register_opt(cfg.StrOpt('project_id'), group='keymanager')
CONF.register_opt(cfg.IntOpt('max_payload_size', default=10000),
                             group='keymanager')
CONF.register_opt(cfg.StrOpt('project_domain_name'), group='keymanager')
