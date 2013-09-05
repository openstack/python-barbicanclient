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

import json

import mock
import unittest2 as unittest

from barbicanclient import client
from barbicanclient.common import auth


class FakeAuth(object):
    def __init__(self, auth_token, barbican_url, tenant_name, tenant_id):
        self.auth_token = auth_token
        self.barbican_url = barbican_url
        self.tenant_name = tenant_name
        self.tenant_id = tenant_id


class WhenTestingClient(unittest.TestCase):
    def setUp(self):
        self.auth_endpoint = 'https://localhost:5000/v2.0/'
        self.auth_token = 'fake_auth_token'
        self.user = 'user'
        self.password = 'password'
        self.tenant_name = 'tenant'
        self.tenant_id = 'tenant_id'

        self.endpoint = 'http://localhost:9311/v1/'

        self.fake_auth = FakeAuth(self.auth_token, self.endpoint,
                                  self.tenant_name, self.tenant_id)

    def test_can_be_used_without_auth_plugin(self):
        c = client.Client(auth_plugin=None, endpoint=self.endpoint,
                          tenant_id=self.tenant_id)
        self.assertNotIn('X-Auth-Token', c._session.headers)

    def test_auth_token_header_is_set_when_using_auth_plugin(self):
        c = client.Client(auth_plugin=self.fake_auth)
        self.assertIn('X-Auth-Token', c._session.headers)
        self.assertEqual(c._session.headers.get('X-Auth-Token'),
                         self.auth_token)

    def test_error_thrown_when_no_auth_and_no_endpoint(self):
        with self.assertRaises(ValueError):
            c = client.Client(tenant_id=self.tenant_id)

    def test_error_thrown_when_no_auth_and_no_tenant_id(self):
        with self.assertRaises(ValueError):
            c = client.Client(endpoint=self.endpoint)

    def test_client_strips_trailing_slash_from_endpoint(self):
        c = client.Client(endpoint=self.endpoint, tenant_id=self.tenant_id)
        self.assertEqual(c._barbican_url, self.endpoint.strip('/'))

    def test_base_url_ends_with_tenant_id(self):
        c = client.Client(auth_plugin=self.fake_auth)
        self.assertTrue(c.base_url.endswith(self.tenant_id))

    def test_should_raise_for_unauthorized_response(self):
        resp = mock.MagicMock()
        resp.status_code = 401
        c = client.Client(auth_plugin=self.fake_auth)
        with self.assertRaises(client.HTTPAuthError):
            c._check_status_code(resp)

    def test_should_raise_for_server_error(self):
        resp = mock.MagicMock()
        resp.status_code = 500
        c = client.Client(auth_plugin=self.fake_auth)
        with self.assertRaises(client.HTTPServerError):
            c._check_status_code(resp)

    def test_should_raise_for_client_errors(self):
        resp = mock.MagicMock()
        resp.status_code = 400
        c = client.Client(auth_plugin=self.fake_auth)
        with self.assertRaises(client.HTTPClientError):
            c._check_status_code(resp)
