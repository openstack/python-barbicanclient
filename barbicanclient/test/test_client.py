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
from barbicanclient import secrets
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


class SecretData(object):
    def __init__(self):
        self.name = 'Self destruction sequence'
        self.payload = 'the magic words are squeamish ossifrage'
        self.payload_content_type = 'text/plain'
        self.content = 'text/plain'
        self.algorithm = 'AES'
        self.created = str(timeutils.utcnow())

        self.secret_dict = {'name': self.name,
                            'status': 'ACTIVE',
                            'algorithm': self.algorithm,
                            'created': self.created}

    def get_dict(self, secret_ref, content_types_dict=None):
        secret_dict = self.secret_dict
        secret_dict['secret_ref'] = secret_ref
        if content_types_dict:
            secret_dict['content_types'] = content_types_dict
        return secret_dict


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


class WhenTestingClientWithSession(unittest.TestCase):
    def setUp(self):
        self.endpoint = 'https://localhost:9311/v1/'
        self.tenant_id = '1234567'

        self.entity = 'dummy-entity'
        self.entity_base = self.endpoint + self.tenant_id + "/" + self.entity + "/"
        self.entity_href = self.entity_base + '1234'

        self.entity_name = 'name'
        self.entity_dict = {'name':  self.entity_name}

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
        self.entity_base = self.endpoint + self.tenant_id + "/" + self.entity + "/"
        self.entity_href = self.entity_base + '1234'

        self.api = mock.MagicMock()
#
#
# class WhenTestingSecretsManager(BaseEntityResource):
#
#     def setUp(self):
#         self._setUp('secrets')
#
#         self.secret = SecretData()
#
#         self.manager = secrets.SecretManager(self.api)
#
#     def test_should_store(self):
#         self.api.post.return_value = {'secret_ref': self.entity_href}
#
#         secret_href = self.manager\
#             .store(name=self.secret.name,
#                    payload=self.secret.payload,
#                    payload_content_type=self.secret.content)
#
#         self.assertEqual(self.entity_href, secret_href)
#
#         # Verify the correct URL was used to make the call.
#         args, kwargs = self.api.post.call_args
#         entity_resp = args[0]
#         self.assertEqual(self.entity, entity_resp)
#
#         # Verify that correct information was sent in the call.
#         secret_resp = args[1]
#         self.assertEqual(self.secret.name, secret_resp['name'])
#         self.assertEqual(self.secret.payload, secret_resp['payload'])
#         self.assertEqual(self.secret.payload_content_type,
#                          secret_resp['payload_content_type'])
#
#     def test_should_get(self):
#         self.api.get.return_value = self.secret.get_dict(self.entity_href)
#
#         secret = self.manager.get(secret_ref=self.entity_href)
#         self.assertIsInstance(secret, secrets.Secret)
#         self.assertEqual(self.entity_href, secret.secret_ref)
#
#         # Verify the correct URL was used to make the call.
#         args, kwargs = self.api.get.call_args
#         url = args[0]
#         self.assertEqual(self.entity_href, url)
#
#     def test_should_decrypt_with_content_type(self):
#         decrypted = 'decrypted text here'
#         self.api.get_raw.return_value = decrypted
#
#         secret = self.manager.decrypt(secret_ref=self.entity_href,
#                                       content_type='application/octet-stream')
#         self.assertEqual(decrypted, secret)
#
#         # Verify the correct URL was used to make the call.
#         args, kwargs = self.api.get_raw.call_args
#         url = args[0]
#         self.assertEqual(self.entity_href, url)
#
#         # Verify that correct information was sent in the call.
#         headers = args[1]
#         self.assertEqual('application/octet-stream', headers['Accept'])
#
#     def test_should_decrypt_without_content_type(self):
#         content_types_dict = {'default': 'application/octet-stream'}
#         self.api.get.return_value = self.secret.get_dict(self.entity_href,
#                                                          content_types_dict)
#         decrypted = 'decrypted text here'
#         self.api.get_raw.return_value = decrypted
#
#         secret = self.manager.decrypt(secret_ref=self.entity_href)
#         self.assertEqual(decrypted, secret)
#
#         # Verify the correct URL was used to make the call.
#         args, kwargs = self.api.get.call_args
#         url = args[0]
#         self.assertEqual(self.entity_href, url)
#
#         # Verify the correct URL was used to make the call.
#         args, kwargs = self.api.get_raw.call_args
#         url = args[0]
#         self.assertEqual(self.entity_href, url)
#
#         # Verify that correct information was sent in the call.
#         headers = args[1]
#         self.assertEqual('application/octet-stream', headers['Accept'])
#
#     def test_should_delete(self):
#         self.manager.delete(secret_ref=self.entity_href)
#
#         # Verify the correct URL was used to make the call.
#         args, kwargs = self.api.delete.call_args
#         url = args[0]
#         self.assertEqual(self.entity_href, url)
#
#     def test_should_fail_get_no_href(self):
#         with self.assertRaises(ValueError):
#             self.manager.get(None)
#
#     def test_should_fail_decrypt_no_content_types(self):
#         self.api.get.return_value = self.secret.get_dict(self.entity_href)
#
#         with self.assertRaises(ValueError):
#             self.manager.decrypt(secret_ref=self.entity_href)
#
#     def test_should_fail_decrypt_no_default_content_type(self):
#         content_types_dict = {'no-default': 'application/octet-stream'}
#         self.api.get.return_value = self.secret.get_dict(self.entity_href,
#                                                          content_types_dict)
#
#         with self.assertRaises(ValueError):
#             self.manager.decrypt(secret_ref=self.entity_href)
#
#     def test_should_fail_delete_no_href(self):
#         with self.assertRaises(ValueError):
#             self.manager.delete(None)


# class WhenTestingVerificationsResourcePost(BaseEntityResource):
#
#     def setUp(self):
#         self._setUp('verifications')
#
#         self.resource_type = 'image'
#         self.resource_ref = 'https://localhost:9311/v1/images/1234567'
#         self.resource_action = 'vm_attach'
#         self.impersonation_allowed = True
#
#     def test_should_create(self):
#         self.session.post.return_value = FakeResp(200, {'verification_ref':
#                                                         self.entity_href})
#
#         verif_href = self.client\
#             .verifications.create(resource_type=self.resource_type,
#                                   resource_ref=self.resource_ref,
#                                   resource_action=self.resource_action)
#
#         self.assertEqual(self.entity_href, verif_href)
#
#         # Verify the correct URL was used to make the call.
#         args, kwargs = self.session.post.call_args
#         url = args[0]
#         self.assertEqual(self.entity_base, url)
#
#         # Verify that correct information was sent in the call.
#         data = jsonutils.loads(kwargs['data'])
#         self.assertEqual(self.resource_type, data['resource_type'])
#         self.assertEqual(self.resource_action, data['resource_action'])
#
#
# class WhenTestingVerificationsResourceGet(BaseEntityResource):
#
#     def setUp(self):
#         self._setUp('verifications')
#
#         self.secret = SecretData()
#
#     def test_should_get(self):
#         self.session.get.return_value = FakeResp(200,
#                                                  self.secret.get_dict())
#
#         secret = self.client.secrets.get(secret_ref=self.entity_href)
#         self.assertIsInstance(secret, secrets.Secret)
#         self.assertEqual(self.entity_href, secret.secret_ref)
#
#         # Verify the correct URL was used to make the call.
#         args, kwargs = self.session.get.call_args
#         url = args[0]
#         self.assertEqual(self.entity_href, url)
#
#         # Verify that correct information was sent in the call.
#         self.assertIsNone(kwargs['params'])
