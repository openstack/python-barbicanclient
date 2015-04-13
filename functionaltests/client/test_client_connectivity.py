# Copyright (c) 2015 Ericsson AB.
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
import logging

from functionaltests.base import BaseTestCase
from barbicanclient import client
from keystoneclient.auth import identity
from keystoneclient import session
from tempest import config

CONF = config.CONF


class WhenTestingClientConnectivity(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(WhenTestingClientConnectivity, cls).setUpClass()
        if 'v2' in CONF.identity.auth_version:
            cls.auth = identity.v2.Password(
                auth_url=CONF.identity.uri,
                username=CONF.keymanager.username,
                password=CONF.keymanager.password,
                tenant_name=CONF.keymanager.project_name)
        else:
            cls.auth = identity.v3.Password(
                auth_url=CONF.identity.uri_v3,
                username=CONF.keymanager.username,
                user_domain_name=CONF.identity.domain_name,
                password=CONF.keymanager.password,
                project_name=CONF.keymanager.project_name,
                project_domain_name=CONF.keymanager.project_domain_name)

        # enables the tests in this class to share a keystone token
        cls.sess = session.Session(auth=cls.auth)

    def setUp(self):
        self.LOG.info('Starting: %s', self._testMethodName)
        super(WhenTestingClientConnectivity, self).setUp()

    def assert_client_can_contact_barbican(self, client):
        """Asserts that the client has connectivity to Barbican.

        If there was an error with the connectivity, the operations that are
        attempted through the client would throw an exception.
        """
        containers = client.containers.list()
        orders = client.orders.list()
        secrets = client.secrets.list()

        self.assertIsNotNone(containers)
        self.assertIsNotNone(orders)
        self.assertIsNotNone(secrets)

    def test_can_access_server_if_endpoint_and_session_specified(self):
        barbicanclient = client.Client(
            endpoint=CONF.keymanager.url,
            project_id=CONF.keymanager.project_id,
            session=self.sess)

        self.assert_client_can_contact_barbican(barbicanclient)

    def test_client_can_access_server_if_no_endpoint_specified(self):
        barbicanclient = client.Client(
            project_id=CONF.keymanager.project_id,
            session=self.sess)

        self.assert_client_can_contact_barbican(barbicanclient)

    def test_client_can_access_server_if_no_session_specified(self):
        barbicanclient = client.Client(
            endpoint=CONF.keymanager.url,
            project_id=CONF.keymanager.project_id,
            auth=self.auth)

        self.assert_client_can_contact_barbican(barbicanclient)
