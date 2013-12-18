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

import mock
import requests
import unittest2 as unittest

from barbicanclient import client
from barbicanclient.openstack.common import timeutils
from barbicanclient.openstack.common import jsonutils


class FakeAuth(object):
    def __init__(self, auth_token, barbican_url, tenant_name, tenant_id):
        self.auth_token = auth_token
        self.barbican_url = barbican_url
        self.tenant_name = tenant_name
        self.tenant_id = tenant_id


class FakeResp(object):
    def __init__(self, status_code, response_dict=None, content=None):
        self.status_code = status_code
        self.response_dict = response_dict
        self.content = content

    def json(self):
        if self.response_dict is None:
            return None
        resp = self.response_dict
        resp['title'] = 'some title here'
        return resp

    def content(self):
        return self.content


class WhenTestingClientInit(unittest.TestCase):
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

    def _mock_response(self, content=None, status_code=200):
        resp = requests.Response()
        resp._content = content or '{"title": {"generic mocked response"}}'
        resp.status_code = status_code
        return resp

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
        resp = self._mock_response(status_code=401)
        c = client.Client(auth_plugin=self.fake_auth)
        with self.assertRaises(client.HTTPAuthError):
            c._check_status_code(resp)

    def test_should_raise_for_server_error(self):
        resp = self._mock_response(status_code=500)
        c = client.Client(auth_plugin=self.fake_auth)
        with self.assertRaises(client.HTTPServerError):
            c._check_status_code(resp)

    def test_should_raise_for_client_errors(self):
        resp = self._mock_response(status_code=400)
        c = client.Client(auth_plugin=self.fake_auth)
        with self.assertRaises(client.HTTPClientError):
            c._check_status_code(resp)


class WhenTestingClientWithSession(unittest.TestCase):
    def setUp(self):
        self.endpoint = 'https://localhost:9311/v1/'
        self.tenant_id = '1234567'

        self.entity = 'dummy-entity'
        base = self.endpoint + self.tenant_id + "/"
        self.entity_base = base + self.entity + "/"
        self.entity_href = self.entity_base + \
            'abcd1234-eabc-5678-9abc-abcdef012345'

        self.entity_name = 'name'
        self.entity_dict = {'name': self.entity_name}

        self.session = mock.MagicMock()

        self.client = client.Client(session=self.session,
                                    endpoint=self.endpoint,
                                    tenant_id=self.tenant_id)

    def test_should_post(self):
        self.session.post.return_value = FakeResp(200, {'entity_ref':
                                                        self.entity_href})

        resp_dict = self.client.post(self.entity, self.entity_dict)

        self.assertEqual(self.entity_href, resp_dict['entity_ref'])

        # Verify the correct URL was used to make the call.
        args, kwargs = self.session.post.call_args
        url = args[0]
        self.assertEqual(self.entity_base, url)

        # Verify that correct information was sent in the call.
        data = jsonutils.loads(kwargs['data'])
        self.assertEqual(self.entity_name, data['name'])

    def test_should_get(self):
        self.session.get.return_value = FakeResp(200, {'name':
                                                       self.entity_name})

        resp_dict = self.client.get(self.entity_href)

        self.assertEqual(self.entity_name, resp_dict['name'])

        # Verify the correct URL was used to make the call.
        args, kwargs = self.session.get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify that correct information was sent in the call.
        headers = kwargs['headers']
        self.assertEqual('application/json', headers['Accept'])

    def test_should_get_raw(self):
        self.session.get.return_value = FakeResp(200, content='content')

        headers = {'Accept': 'application/octet-stream'}
        content = self.client.get_raw(self.entity_href, headers)

        self.assertEqual('content', content)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.session.get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify that correct information was sent in the call.
        headers = kwargs['headers']
        self.assertEqual('application/octet-stream', headers['Accept'])

    def test_should_delete(self):
        self.session.delete.return_value = FakeResp(200)

        self.client.delete(self.entity_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.session.delete.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)


class BaseEntityResource(unittest.TestCase):
    def _setUp(self, entity):
        self.endpoint = 'https://localhost:9311/v1/'
        self.tenant_id = '1234567'

        self.entity = entity
        base = self.endpoint + self.tenant_id + "/"
        self.entity_base = base + self.entity + "/"
        self.entity_href = self.entity_base + \
            'abcd1234-eabc-5678-9abc-abcdef012345'

        self.api = mock.MagicMock()
        self.api.base_url = base[:-1]
