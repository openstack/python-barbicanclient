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
import requests
import testtools

from barbicanclient.common import auth


class WhenTestingKeystoneAuthentication(testtools.TestCase):

    def setUp(self):
        super(WhenTestingKeystoneAuthentication, self).setUp()
        self.keystone_client = mock.MagicMock()

        self.auth_url = 'https://www.yada.com'
        self.username = 'user'
        self.password = 'pw'
        self.tenant_name = 'tenant'
        self.tenant_id = '1234'

        self.keystone_auth = auth.KeystoneAuthV2(auth_url=self.auth_url,
                                                 username=self.username,
                                                 password=self.password,
                                                 tenant_name=self.tenant_name,
                                                 tenant_id=self.tenant_id,
                                                 keystone=self.keystone_client)

    def test_endpoint_username_password_tenant_are_required(self):
        with testtools.ExpectedException(ValueError):
            auth.KeystoneAuthV2()

    def test_nothing_is_required_if_keystone_is_present(self):
        fake_keystone = mock.Mock(tenant_name='foo', tenant_id='bar')
        keystone_auth = auth.KeystoneAuthV2(keystone=fake_keystone)
        self.assertEqual('foo', keystone_auth.tenant_name)
        self.assertEqual('bar', keystone_auth.tenant_id)

    def test_get_barbican_url(self):
        barbican_url = 'https://www.barbican.com'
        self.keystone_auth._barbican_url = barbican_url
        self.assertEquals(barbican_url, self.keystone_auth.barbican_url)


class WhenTestingRackspaceAuthentication(testtools.TestCase):

    def setUp(self):
        super(WhenTestingRackspaceAuthentication, self).setUp()
        self._auth_url = 'https://auth.url.com'
        self._username = 'username'
        self._api_key = 'api_key'
        self._auth_token = '078a50dcdc984a639bb287c8d4adf541'
        self._tenant_id = '123456'

        self._response = requests.Response()
        self._response._content = json.dumps({
            'access': {
                'token': {
                    'id': self._auth_token,
                    'expires': '2013-12-19T23:06:17.047Z',
                    'tenant': {
                        'id': self._tenant_id,
                        'name': '123456'
                    }
                }
            }
        }).encode("ascii")

        patcher = mock.patch('barbicanclient.common.auth.requests.post')
        self._mock_post = patcher.start()
        self._mock_post.return_value = self._response
        self.addCleanup(patcher.stop)

    def test_auth_url_username_and_api_key_are_required(self):
        with testtools.ExpectedException(ValueError):
            auth.RackspaceAuthV2()
        with testtools.ExpectedException(ValueError):
            auth.RackspaceAuthV2(self._auth_url)
        with testtools.ExpectedException(ValueError):
            auth.RackspaceAuthV2(self._auth_url,
                                 self._username)
        with testtools.ExpectedException(ValueError):
            auth.RackspaceAuthV2(self._auth_url,
                                 api_key=self._api_key)

    def test_tokens_is_appended_to_auth_url(self):
        self._response.status_code = 200
        identity = auth.RackspaceAuthV2(self._auth_url,
                                        self._username,
                                        api_key=self._api_key)
        self._mock_post.assert_called_with(
            'https://auth.url.com/tokens',
            data=mock.ANY,
            headers=mock.ANY)

    def test_authenticate_with_api_key(self):
        self._response.status_code = 200
        with mock.patch(
            'barbicanclient.common.auth.RackspaceAuthV2.'
            '_authenticate_with_api_key'
        ) as mock_authenticate:
            mock_authenticate.return_value = {}
            identity = auth.RackspaceAuthV2(self._auth_url,
                                            self._username,
                                            api_key=self._api_key)
            mock_authenticate.assert_called_once_with()

    def test_authenticate_with_password(self):
        self._response.status_code = 200
        with mock.patch(
            'barbicanclient.common.auth.RackspaceAuthV2.'
            '_authenticate_with_password'
        ) as mock_authenticate:
            mock_authenticate.return_value = {}
            identity = auth.RackspaceAuthV2(self._auth_url,
                                            self._username,
                                            password='password')
            mock_authenticate.assert_called_once_with()

    def test_auth_exception_thrown_for_bad_status(self):
        self._response.status_code = 400
        with testtools.ExpectedException(auth.AuthException):
            auth.RackspaceAuthV2(self._auth_url,
                                 self._username,
                                 api_key=self._api_key)

    def test_error_raised_for_bad_response_from_server(self):
        self._response._content = b'Not JSON'
        self._response.status_code = 200
        with testtools.ExpectedException(auth.AuthException):
            auth.RackspaceAuthV2(self._auth_url,
                                 self._username,
                                 api_key=self._api_key)

    def test_auth_token_is_set(self):
        self._response.status_code = 200
        identity = auth.RackspaceAuthV2(self._auth_url,
                                        self._username,
                                        api_key=self._api_key)
        self.assertEqual(identity.auth_token, self._auth_token)

    def test_tenant_id_is_set(self):
        self._response.status_code = 200
        identity = auth.RackspaceAuthV2(self._auth_url,
                                        self._username,
                                        api_key=self._api_key)
        self.assertEqual(identity.tenant_id, self._tenant_id)
