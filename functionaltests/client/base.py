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
import logging

from functionaltests.base import BaseTestCase
from barbicanclient import client
from keystoneclient.auth import identity
from keystoneclient import session
from tempest import config

CONF = config.CONF


class TestCase(BaseTestCase):

    def setUp(self):
        self.LOG.info('Starting: %s', self._testMethodName)
        super(TestCase, self).setUp()

        if 'v2' in CONF.identity.auth_version:
            self.auth = identity.v2.Password(
                auth_url=CONF.identity.uri,
                username=CONF.keymanager.username,
                password=CONF.keymanager.password,
                tenant_name=CONF.keymanager.project_name)
        else:
            self.auth = identity.v3.Password(
                auth_url=CONF.identity.uri_v3,
                username=CONF.keymanager.username,
                user_domain_name=CONF.identity.domain_name,
                password=CONF.keymanager.password,
                project_name=CONF.keymanager.project_name,
                project_domain_name=CONF.keymanager.project_domain_name)

        self.sess = session.Session(auth=self.auth)
        self.barbicanclient = client.Client(
            endpoint=CONF.keymanager.url,
            project_id=CONF.keymanager.project_id,
            session=self.sess)
