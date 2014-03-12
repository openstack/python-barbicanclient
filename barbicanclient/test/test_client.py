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
import httpretty
import requests
import testtools
import json
import uuid

from barbicanclient import client
from barbicanclient.test import keystone_client_fixtures
from barbicanclient.openstack.common import timeutils
from barbicanclient.openstack.common import jsonutils

from keystoneclient import session as ks_session
from keystoneclient.auth.identity import v2
from keystoneclient.auth.identity import v3


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


class KeystonePasswordPlugins(object):
    v2_auth_url = keystone_client_fixtures.V2_URL
    v3_auth_url = keystone_client_fixtures.V3_URL
    username = 'username'
    password = 'password'
    project_name = tenant_name = 'tenantname'
    tenant_id = project_id = 'tenantid'
    user_domain_name = 'udomain_name'
    user_domain_id = 'udomain_id'
    project_domain_name = 'pdomain_name'
    project_domain_id = 'pdomain_id'

    @classmethod
    def get_v2_plugin(cls):
        return v2.Password(auth_url=cls.v2_auth_url, username=cls.username,
                           password=cls.password, tenant_name=cls.tenant_name)

    @classmethod
    def get_v3_plugin(cls):
        return v3.Password(auth_url=cls.v3_auth_url, username=cls.username,
                           password=cls.password,
                           project_name=cls.project_name,
                           user_domain_name=cls.user_domain_name,
                           project_domain_name=cls.project_domain_name)


class WhenTestingClientInit(testtools.TestCase):

    def setUp(self):
        super(WhenTestingClientInit, self).setUp()
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
        resp._content = content or b'{"title": "generic mocked response"}'
        resp.status_code = status_code
        return resp

    def test_can_be_used_without_auth_plugin(self):
        c = client.Client(auth_plugin=None, endpoint=self.endpoint,
                          tenant_id=self.tenant_id)
        expected = '%s%s' % (self.endpoint, self.tenant_id)
        self.assertEqual(expected, c.base_url)

    def test_auth_token_header_is_set_when_using_auth_plugin(self):
        c = client.Client(auth_plugin=self.fake_auth)
        self.assertEqual(c._session.get_token(),
                         self.auth_token)

    def test_error_thrown_when_no_auth_and_no_endpoint(self):
        self.assertRaises(ValueError, client.Client,
                          **{"tenant_id": self.tenant_id})

    def test_error_thrown_when_no_auth_and_no_tenant_id(self):
        self.assertRaises(ValueError, client.Client,
                          **{"endpoint": self.endpoint})

    def test_client_strips_trailing_slash_from_endpoint(self):
        c = client.Client(endpoint=self.endpoint, tenant_id=self.tenant_id)
        self.assertEqual(c._barbican_url, self.endpoint.strip('/'))

    def test_base_url_starts_with_endpoint_url(self):
        c = client.Client(auth_plugin=self.fake_auth)
        self.assertTrue(c.base_url.startswith(self.endpoint))

    def test_base_url_ends_with_tenant_id(self):
        c = client.Client(auth_plugin=self.fake_auth)
        self.assertTrue(c.base_url.endswith(self.tenant_id))

    def test_should_raise_for_unauthorized_response(self):
        resp = self._mock_response(status_code=401)
        c = client.Client(auth_plugin=self.fake_auth)
        self.assertRaises(client.HTTPAuthError, c._check_status_code, resp)

    def test_should_raise_for_server_error(self):
        resp = self._mock_response(status_code=500)
        c = client.Client(auth_plugin=self.fake_auth)
        self.assertRaises(client.HTTPServerError, c._check_status_code, resp)

    def test_should_raise_for_client_errors(self):
        resp = self._mock_response(status_code=400)
        c = client.Client(auth_plugin=self.fake_auth)
        self.assertRaises(client.HTTPClientError, c._check_status_code, resp)


class WhenTestingClientWithSession(testtools.TestCase):

    def setUp(self):
        super(WhenTestingClientWithSession, self).setUp()
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
        self.session.request.return_value = mock.MagicMock(status_code=200)
        self.session.request.return_value.json.return_value = {
            'entity_ref': self.entity_href}

        resp_dict = self.client.post(self.entity, self.entity_dict)

        self.assertEqual(self.entity_href, resp_dict['entity_ref'])

        # Verify the correct URL was used to make the call.
        args, kwargs = self.session.request.call_args
        url = args[1]
        self.assertEqual(self.entity_base, url)

        # Verify that correct information was sent in the call.
        data = jsonutils.loads(kwargs['data'])
        self.assertEqual(self.entity_name, data['name'])

    def test_should_get(self):
        self.session.request.return_value = mock.MagicMock(status_code=200)
        self.session.request.return_value.json.return_value = {
            'name': self.entity_name}
        resp_dict = self.client.get(self.entity_href)

        self.assertEqual(self.entity_name, resp_dict['name'])

        # Verify the correct URL was used to make the call.
        args, kwargs = self.session.request.call_args
        url = args[1]
        self.assertEqual(self.entity_href, url)

        # Verify that correct information was sent in the call.
        headers = kwargs['headers']
        self.assertEqual('application/json', headers['Accept'])

    def test_should_get_raw(self):
        self.session.request.return_value = mock.MagicMock(status_code=200,
                                                           content='content')

        headers = {'Accept': 'application/octet-stream'}
        content = self.client.get_raw(self.entity_href, headers)

        self.assertEqual('content', content)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.session.request.call_args
        url = args[1]
        self.assertEqual(self.entity_href, url)

        # Verify that correct information was sent in the call.
        headers = kwargs['headers']
        self.assertEqual('application/octet-stream', headers['Accept'])

    def test_should_delete(self):
        self.session.request.return_value = mock.MagicMock(status_code=200)

        self.client.delete(self.entity_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.session.request.call_args
        url = args[1]
        self.assertEqual(self.entity_href, url)


class WhenTestingClientWithKeystoneV2(WhenTestingClientWithSession):

    def setUp(self):
        super(WhenTestingClientWithKeystoneV2, self).setUp()

    @httpretty.activate
    def test_should_get(self):
        # emulate Keystone version discovery
        httpretty.register_uri(httpretty.GET,
                               keystone_client_fixtures.V2_URL,
                               body=keystone_client_fixtures.V2_VERSION_ENTRY)
        # emulate Keystone v2 token request
        v2_token = keystone_client_fixtures.generate_v2_project_scoped_token()
        httpretty.register_uri(httpretty.POST,
                               '%s/tokens' % (keystone_client_fixtures.V2_URL),
                               body=json.dumps(v2_token))
        auth_plugin = KeystonePasswordPlugins.get_v2_plugin()
        c = client.Client(auth_plugin=auth_plugin)
        # emulate list secrets
        list_secrets_url = '%s/secrets' % (c.base_url)
        httpretty.register_uri(
            httpretty.GET,
            list_secrets_url,
            status=200,
            body='{"name": "%s", "secret_ref": "%s"}' %
                 (self.entity_name, self.entity_href))
        resp = c.get(list_secrets_url)
        self.assertEqual(self.entity_name, resp['name'])
        self.assertEqual(self.entity_href, resp['secret_ref'])

    @httpretty.activate
    def test_should_post(self):
        # emulate Keystone version discovery
        httpretty.register_uri(httpretty.GET,
                               keystone_client_fixtures.V2_URL,
                               body=keystone_client_fixtures.V2_VERSION_ENTRY)
        # emulate Keystone v2 token request
        v2_token = keystone_client_fixtures.generate_v2_project_scoped_token()
        httpretty.register_uri(httpretty.POST,
                               '%s/tokens' % (keystone_client_fixtures.V2_URL),
                               body=json.dumps(v2_token))
        auth_plugin = KeystonePasswordPlugins.get_v2_plugin()
        c = client.Client(auth_plugin=auth_plugin)
        # emulate list secrets
        post_secret_url = '%s/secrets/' % (c.base_url)
        httpretty.register_uri(
            httpretty.POST,
            post_secret_url,
            status=200,
            body='{"name": "%s", "secret_ref": "%s"}'
                 % (self.entity_name, self.entity_href))
        resp = c.post('secrets', '{"name":"test"}')
        self.assertEqual(self.entity_name, resp['name'])
        self.assertEqual(self.entity_href, resp['secret_ref'])

    @httpretty.activate
    def test_should_get_raw(self):
        # emulate Keystone version discovery
        httpretty.register_uri(httpretty.GET,
                               keystone_client_fixtures.V2_URL,
                               body=keystone_client_fixtures.V2_VERSION_ENTRY)
        # emulate Keystone v2 token request
        v2_token = keystone_client_fixtures.generate_v2_project_scoped_token()
        httpretty.register_uri(httpretty.POST,
                               '%s/tokens' % (keystone_client_fixtures.V2_URL),
                               body=json.dumps(v2_token))
        auth_plugin = KeystonePasswordPlugins.get_v2_plugin()
        c = client.Client(auth_plugin=auth_plugin)
        # emulate list secrets
        get_secret_url = '%s/secrets/s1' % (c.base_url)
        httpretty.register_uri(
            httpretty.GET,
            get_secret_url,
            status=200, body='content')
        headers = {"Content-Type": "application/json"}
        resp = c.get_raw(get_secret_url, headers)
        self.assertEqual(b'content', resp)

    @httpretty.activate
    def test_should_delete(self):
        # emulate Keystone version discovery
        httpretty.register_uri(httpretty.GET,
                               keystone_client_fixtures.V2_URL,
                               body=keystone_client_fixtures.V2_VERSION_ENTRY)
        # emulate Keystone v2 token request
        v2_token = keystone_client_fixtures.generate_v2_project_scoped_token()
        httpretty.register_uri(httpretty.POST,
                               '%s/tokens' % (keystone_client_fixtures.V2_URL),
                               body=json.dumps(v2_token))
        auth_plugin = KeystonePasswordPlugins.get_v2_plugin()
        c = client.Client(auth_plugin=auth_plugin)
        # emulate list secrets
        delete_secret_url = '%s/secrets/s1' % (c.base_url)
        httpretty.register_uri(
            httpretty.DELETE,
            delete_secret_url,
            status=201)
        c.delete(delete_secret_url)


class WhenTestingClientWithKeystoneV3(WhenTestingClientWithSession):

    def setUp(self):
        super(WhenTestingClientWithKeystoneV3, self).setUp()

    @httpretty.activate
    def test_should_get(self):
        # emulate Keystone version discovery
        httpretty.register_uri(httpretty.GET,
                               keystone_client_fixtures.V3_URL,
                               body=keystone_client_fixtures.V3_VERSION_ENTRY)
        # emulate Keystone v3 token request
        id, v3_token = keystone_client_fixtures.\
            generate_v3_project_scoped_token()
        httpretty.register_uri(httpretty.POST,
                               '%s/auth/tokens' % (
                                   keystone_client_fixtures.V3_URL),
                               body=json.dumps(v3_token), x_subject_token=id)
        auth_plugin = KeystonePasswordPlugins.get_v3_plugin()
        c = client.Client(auth_plugin=auth_plugin)
        # emulate list secrets
        list_secrets_url = '%s/secrets' % (c.base_url)
        httpretty.register_uri(
            httpretty.GET,
            list_secrets_url,
            status=200,
            body='{"name": "%s", "secret_ref": "%s"}'
                 % (self.entity_name, self.entity_href))
        resp = c.get(list_secrets_url)
        self.assertEqual(self.entity_name, resp['name'])
        self.assertEqual(self.entity_href, resp['secret_ref'])

    @httpretty.activate
    def test_should_post(self):
        # emulate Keystone version discovery
        httpretty.register_uri(httpretty.GET,
                               keystone_client_fixtures.V3_URL,
                               body=keystone_client_fixtures.V3_VERSION_ENTRY)
        # emulate Keystone v3 token request
        id, v3_token = keystone_client_fixtures.\
            generate_v3_project_scoped_token()
        httpretty.register_uri(httpretty.POST,
                               '%s/auth/tokens' % (
                                   keystone_client_fixtures.V3_URL),
                               body=json.dumps(v3_token),
                               x_subject_token=id)
        auth_plugin = KeystonePasswordPlugins.get_v3_plugin()
        c = client.Client(auth_plugin=auth_plugin)
        # emulate list secrets
        post_secret_url = '%s/secrets/' % (c.base_url)
        httpretty.register_uri(
            httpretty.POST,
            post_secret_url,
            status=200,
            x_subject_token=id,
            body='{"name": "%s", "secret_ref": "%s"}'
                 % (self.entity_name, self.entity_href))
        resp = c.post('secrets', '{"name":"test"}')
        self.assertEqual(self.entity_name, resp['name'])
        self.assertEqual(self.entity_href, resp['secret_ref'])

    @httpretty.activate
    def test_should_get_raw(self):
        # emulate Keystone version discovery
        httpretty.register_uri(httpretty.GET,
                               keystone_client_fixtures.V3_URL,
                               body=keystone_client_fixtures.V3_VERSION_ENTRY)
        # emulate Keystone v3 token request
        id, v3_token = keystone_client_fixtures.\
            generate_v3_project_scoped_token()
        httpretty.register_uri(httpretty.POST,
                               '%s/auth/tokens' % (
                                   keystone_client_fixtures.V3_URL),
                               body=json.dumps(v3_token),
                               x_subject_token=id)
        auth_plugin = KeystonePasswordPlugins.get_v3_plugin()
        c = client.Client(auth_plugin=auth_plugin)
        # emulate list secrets
        get_secret_url = '%s/secrets/s1' % (c.base_url)
        httpretty.register_uri(
            httpretty.GET,
            get_secret_url,
            status=200, body='content')
        headers = {"Content-Type": "application/json"}
        resp = c.get_raw(get_secret_url, headers)
        self.assertEqual(b'content', resp)

    @httpretty.activate
    def test_should_delete(self):
        # emulate Keystone version discovery
        httpretty.register_uri(httpretty.GET,
                               keystone_client_fixtures.V3_URL,
                               body=keystone_client_fixtures.V3_VERSION_ENTRY)
        # emulate Keystone v3 token request
        id, v3_token = keystone_client_fixtures.\
            generate_v3_project_scoped_token()
        httpretty.register_uri(httpretty.POST,
                               '%s/auth/tokens' % (
                                   keystone_client_fixtures.V3_URL),
                               body=json.dumps(v3_token),
                               x_subject_token=id)
        auth_plugin = KeystonePasswordPlugins.get_v3_plugin()
        c = client.Client(auth_plugin=auth_plugin)
        # emulate list secrets
        delete_secret_url = '%s/secrets/s1' % (c.base_url)
        httpretty.register_uri(
            httpretty.DELETE,
            delete_secret_url,
            status=201)
        c.delete(delete_secret_url)


class BaseEntityResource(testtools.TestCase):

    def _setUp(self, entity):
        super(BaseEntityResource, self).setUp()
        self.endpoint = 'https://localhost:9311/v1/'
        self.tenant_id = '1234567'

        self.entity = entity
        base = self.endpoint + self.tenant_id + "/"
        self.entity_base = base + self.entity + "/"
        self.entity_href = self.entity_base + \
            'abcd1234-eabc-5678-9abc-abcdef012345'

        self.api = mock.MagicMock()
        self.api.base_url = base[:-1]
