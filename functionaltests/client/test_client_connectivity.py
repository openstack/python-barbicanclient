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

from barbicanclient import client
from barbicanclient import exceptions
from functionaltests.base import BaseTestCase
from functionaltests.common import config
from keystoneauth1 import exceptions as ks_exceptions
from keystoneauth1 import identity
from keystoneauth1 import session

CONF = config.get_config()


class WhenTestingClientConnectivity(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(WhenTestingClientConnectivity, cls).setUpClass()
        if 'v2' in CONF.identity.auth_version:
            cls.auth = identity.Password(
                auth_url=CONF.identity.uri,
                username=CONF.keymanager.username,
                password=CONF.keymanager.password,
                tenant_name=CONF.keymanager.project_name)
        else:
            cls.auth = identity.Password(
                auth_url=CONF.identity.uri,
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

    def assert_client_cannot_contact_barbican(self, client):
        self.assertRaises(exceptions.HTTPClientError, client.containers.list)
        self.assertRaises(exceptions.HTTPClientError, client.orders.list)
        self.assertRaises(exceptions.HTTPClientError, client.secrets.list)

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

    def test_client_can_access_server_if_endpoint_filters_specified(self):
        barbicanclient = client.Client(
            project_id=CONF.keymanager.project_id,
            auth=self.auth,
            interface=client._DEFAULT_SERVICE_INTERFACE,
            service_type=client._DEFAULT_SERVICE_TYPE,
            version=client._DEFAULT_API_VERSION)

        self.assert_client_can_contact_barbican(barbicanclient)

    def test_client_cannot_access_server_if_endpoint_filter_wrong(self):
        self.assertRaises(
            ks_exceptions.EndpointNotFound,
            client.Client,
            project_id=CONF.keymanager.project_id,
            auth=self.auth,
            interface=client._DEFAULT_SERVICE_INTERFACE,
            service_type='wrong-service-type',
            version=client._DEFAULT_API_VERSION)

        self.assertRaises(
            ks_exceptions.EndpointNotFound,
            client.Client,
            project_id=CONF.keymanager.project_id,
            auth=self.auth,
            interface='wrong-interface',
            service_type=client._DEFAULT_SERVICE_TYPE,
            version=client._DEFAULT_API_VERSION)

        self.assertRaises(
            ks_exceptions.EndpointNotFound,
            client.Client,
            project_id=CONF.keymanager.project_id,
            auth=self.auth,
            interface=client._DEFAULT_SERVICE_INTERFACE,
            service_type=client._DEFAULT_SERVICE_TYPE,
            service_name='wrong-service-name',
            version=client._DEFAULT_API_VERSION)

        self.assertRaises(
            ks_exceptions.EndpointNotFound,
            client.Client,
            project_id=CONF.keymanager.project_id,
            auth=self.auth,
            interface=client._DEFAULT_SERVICE_INTERFACE,
            service_type=client._DEFAULT_SERVICE_TYPE,
            region_name='wrong-region-name',
            version=client._DEFAULT_API_VERSION)

    def test_cannot_create_client_if_nonexistent_version_specified(self):
        self.assertRaises(exceptions.UnsupportedVersion,
                          client.Client,
                          **{"project_id": CONF.keymanager.project_id,
                             "auth": self.auth,
                             "interface": client._DEFAULT_SERVICE_INTERFACE,
                             "service_type": client._DEFAULT_SERVICE_TYPE,
                             "version": 'wrong-version'})

        self.assertRaises(exceptions.UnsupportedVersion,
                          client.Client,
                          **{"endpoint": CONF.keymanager.url,
                             "project_id": CONF.keymanager.project_id,
                             "auth": self.auth,
                             "version": 'nonexistent_version'})

    def test_client_can_access_server_if_no_version_is_specified(self):
        barbicanclient = client.Client(
            project_id=CONF.keymanager.project_id,
            auth=self.auth,
            interface=client._DEFAULT_SERVICE_INTERFACE,
            service_type=client._DEFAULT_SERVICE_TYPE)

        self.assert_client_can_contact_barbican(barbicanclient)
