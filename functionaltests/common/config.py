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

from oslo_config import cfg

TEST_CONF = None


def setup_config(config_file=''):
    global TEST_CONF
    TEST_CONF = cfg.ConfigOpts()

    identity_group = cfg.OptGroup(name='identity')
    identity_options = [
        cfg.StrOpt('uri', default='http://localhost/identity'),
        cfg.StrOpt('auth_version', default='v3'),
        cfg.StrOpt('username', default='admin'),
        cfg.StrOpt('password', default='secretadmin'),
        cfg.StrOpt('tenant_name', default='admin'),
        cfg.StrOpt('domain_name', default='Default'),
        cfg.StrOpt('admin_username', default='admin'),
        cfg.StrOpt('admin_password', default='secretadmin'),
        cfg.StrOpt('admin_tenant_name', default='admin'),
        cfg.StrOpt('admin_domain_name', default='Default')
    ]
    TEST_CONF.register_group(identity_group)
    TEST_CONF.register_opts(identity_options, group=identity_group)

    keymanager_group = cfg.OptGroup(name='keymanager')
    keymanager_options = [
        cfg.StrOpt('url', default='http://localhost:9311'),
        cfg.StrOpt('username', default='admin'),
        cfg.StrOpt('password', default='secretadmin'),
        cfg.StrOpt('project_name', default='admin'),
        cfg.StrOpt('project_id', default='admin'),
        cfg.StrOpt('project_domain_name', default='Default'),
        cfg.IntOpt('max_payload_size', default=10000)
    ]
    TEST_CONF.register_group(keymanager_group)
    TEST_CONF.register_opts(keymanager_options, group=keymanager_group)

    # Figure out which config to load
    config_to_load = []
    local_config = './etc/functional_tests.conf'
    devstack_config = '../etc/functional_tests.conf'
    if os.path.isfile(config_file):
        config_to_load.append(config_file)
    elif os.path.isfile(local_config):
        config_to_load.append(local_config)
    elif os.path.isfile(devstack_config):
        config_to_load.append(devstack_config)
    else:
        config_to_load.append('/etc/functional_tests.conf')

    # Actually parse config
    TEST_CONF(
        (),  # Required to load an anonymous config
        default_config_files=config_to_load
    )


def get_config():
    if not TEST_CONF:
        setup_config()
    return TEST_CONF
