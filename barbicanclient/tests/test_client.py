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

from keystoneclient import session
import mock
from requests_mock.contrib import fixture
import testtools

from barbicanclient import client


class TestClient(testtools.TestCase):

    def setUp(self):
        super(TestClient, self).setUp()
        self.responses = self.useFixture(fixture.Fixture())
        self.endpoint = 'http://localhost:9311'
        self.project_id = 'project_id'
        self.session = session.Session()
        self.httpclient = client._HTTPClient(session=self.session,
                                             endpoint=self.endpoint,
                                             project_id=self.project_id)


class WhenTestingClientInit(TestClient):

    def test_can_be_used_without_a_session(self):
        c = client._HTTPClient(session=self.session,
                               endpoint=self.endpoint,
                               project_id=self.project_id)
        self.assertIsNotNone(c._session)

    def test_api_version_is_appended_to_endpoint(self):
        c = client._HTTPClient(session=self.session,
                               endpoint=self.endpoint,
                               project_id=self.project_id)
        self.assertEqual(c._base_url, 'http://localhost:9311/v1')

    def test_default_headers_are_empty(self):
        c = client._HTTPClient(self.session, self.endpoint)
        self.assertIsInstance(c._default_headers, dict)
        self.assertFalse(bool(c._default_headers))

    def test_project_id_is_added_to_default_headers(self):
        c = client._HTTPClient(session=self.session,
                               endpoint=self.endpoint,
                               project_id=self.project_id)
        self.assertIn('X-Project-Id', c._default_headers.keys())
        self.assertEqual(c._default_headers['X-Project-Id'], self.project_id)

    def test_error_thrown_when_no_session_and_no_endpoint(self):
        self.assertRaises(ValueError, client.Client,
                          **{"project_id": self.project_id})

    def test_error_thrown_when_no_session_and_no_project_id(self):
        self.assertRaises(ValueError, client.Client,
                          **{"endpoint": self.endpoint})

    def test_client_strips_trailing_slash_from_endpoint(self):
        c = client._HTTPClient(session=self.session,
                               endpoint=self.endpoint + '/',
                               project_id=self.project_id)
        self.assertEqual(c._barbican_endpoint, self.endpoint)

    def test_base_url_starts_with_endpoint_url(self):
        c = client._HTTPClient(session=self.session,
                               endpoint=self.endpoint,
                               project_id=self.project_id)
        self.assertTrue(c._base_url.startswith(self.endpoint))

    def test_base_url_ends_with_default_api_version(self):
        c = client._HTTPClient(session=self.session,
                               endpoint=self.endpoint,
                               project_id=self.project_id)
        self.assertTrue(c._base_url.endswith(client._DEFAULT_API_VERSION))

    def test_gets_endpoint_from_keystone_session(self):
        c = client._HTTPClient(session=self.session,
                               endpoint=self.endpoint)
        self.assertEqual(c._barbican_endpoint, self.endpoint)


class WhenTestingClientPost(TestClient):

    def setUp(self):
        super(WhenTestingClientPost, self).setUp()
        self.httpclient = client._HTTPClient(self.session, self.endpoint)
        self.href = self.endpoint + '/v1/secrets/'
        self.post_mock = self.responses.post(self.href, json={})

    def test_post_normalizes_url_with_traling_slash(self):
        self.httpclient._post(path='secrets', data={'test_data': 'test'})
        self.assertTrue(self.post_mock.last_request.url.endswith('/'))

    def test_post_includes_content_type_header_of_application_json(self):
        self.httpclient._post(path='secrets', data={'test_data': 'test'})
        self.assertEqual('application/json',
                         self.post_mock.last_request.headers['Content-Type'])

    def test_post_includes_default_headers(self):
        self.httpclient._default_headers = {'Test-Default-Header': 'test'}
        self.httpclient._post(path='secrets', data={'test_data': 'test'})
        self.assertEqual(
            'test',
            self.post_mock.last_request.headers['Test-Default-Header'])

    def test_post_checks_status_code(self):
        self.httpclient._check_status_code = mock.MagicMock()
        self.httpclient._post(path='secrets', data={'test_data': 'test'})
        self.httpclient._check_status_code.assert_called()


class WhenTestingClientGet(TestClient):

    def setUp(self):
        super(WhenTestingClientGet, self).setUp()
        self.httpclient = client._HTTPClient(self.session, self.endpoint)
        self.headers = dict()
        self.href = 'http://test_href/'
        self.get_mock = self.responses.get(self.href, json={})

    def test_get_uses_href_as_is(self):
        self.httpclient._get(self.href)
        self.assertEqual(self.get_mock.last_request.url, self.href)

    def test_get_passes_params(self):
        params = {'test': 'test1'}
        self.httpclient._get(self.href, params=params)
        self.assertEqual(self.get_mock.last_request.url.split('?')[0],
                         self.href)
        self.assertEqual(['test1'], self.get_mock.last_request.qs['test'])

    def test_get_includes_accept_header_of_application_json(self):
        self.httpclient._get(self.href)
        self.assertEqual('application/json',
                         self.get_mock.last_request.headers['Accept'])

    def test_get_includes_default_headers(self):
        self.httpclient._default_headers = {'Test-Default-Header': 'test'}
        self.httpclient._get(self.href)
        self.assertEqual(
            'test',
            self.get_mock.last_request.headers['Test-Default-Header'])

    def test_get_checks_status_code(self):
        self.httpclient._check_status_code = mock.MagicMock()
        self.httpclient._get(self.href)
        self.httpclient._check_status_code.assert_called()

    def test_get_raw_uses_href_as_is(self):
        self.httpclient._get_raw(self.href, self.headers)
        self.assertEqual(self.get_mock.last_request.url, self.href)

    def test_get_raw_passes_headers(self):
        self.httpclient._get_raw(self.href, {'test': 'test'})
        self.assertEqual('test', self.get_mock.last_request.headers['test'])

    def test_get_raw_includes_default_headers(self):
        self.httpclient._default_headers = {'Test-Default-Header': 'test'}
        self.httpclient._get_raw(self.href, self.headers)
        self.assertIn('Test-Default-Header',
                      self.get_mock.last_request.headers)

    def test_get_raw_checks_status_code(self):
        self.httpclient._check_status_code = mock.MagicMock()
        self.httpclient._get_raw(self.href, self.headers)
        self.httpclient._check_status_code.assert_called()


class WhenTestingClientDelete(TestClient):

    def setUp(self):
        super(WhenTestingClientDelete, self).setUp()
        self.httpclient = client._HTTPClient(session=self.session,
                                             endpoint=self.endpoint)
        self.href = 'http://test_href/'
        self.del_mock = self.responses.delete(self.href, status_code=204)

    def test_delete_uses_href_as_is(self):
        self.httpclient._delete(self.href)
        self.assertTrue(self.del_mock.called)

    def test_delete_passes_json(self):
        json = {"test": "test"}
        self.httpclient._delete(self.href, json=json)
        self.assertEqual(self.del_mock.last_request.text, '{"test": "test"}')

    def test_delete_includes_default_headers(self):
        self.httpclient._default_headers = {'Test-Default-Header': 'test'}
        self.httpclient._delete(self.href)
        self.assertEqual(
            'test',
            self.del_mock.last_request.headers['Test-Default-Header'])

    def test_delete_checks_status_code(self):
        self.httpclient._check_status_code = mock.MagicMock()
        self.httpclient._delete(self.href)
        self.httpclient._check_status_code.assert_called()


class WhenTestingCheckStatusCodes(TestClient):

    def test_raises_http_auth_error_for_401_response(self):
        resp = mock.MagicMock()
        resp.status_code = 401
        self.assertRaises(client.HTTPAuthError,
                          self.httpclient._check_status_code,
                          resp)

    def test_raises_http_server_error_for_500_response(self):
        resp = mock.MagicMock()
        resp.status_code = 500
        self.assertRaises(client.HTTPServerError,
                          self.httpclient._check_status_code, resp)

    def test_raises_http_client_error_for_400_response(self):
        resp = mock.MagicMock()
        resp.status_code = 400
        self.assertRaises(client.HTTPClientError,
                          self.httpclient._check_status_code, resp)


class WhenTestingGetErrorMessage(TestClient):

    def test_gets_error_message_from_title_in_json(self):
        resp = mock.MagicMock()
        resp.json.return_value = {'title': 'test_text'}
        msg = self.httpclient._get_error_message(resp)
        self.assertEqual(msg, 'test_text')

    def test_gets_error_message_from_content_when_no_json(self):
        resp = mock.MagicMock()
        resp.json.side_effect = ValueError()
        resp.content = content = 'content'
        msg = self.httpclient._get_error_message(resp)
        self.assertEqual(msg, content)


class BaseEntityResource(testtools.TestCase):

    def _setUp(self, entity, entity_id='abcd1234-eabc-5678-9abc-abcdef012345'):
        super(BaseEntityResource, self).setUp()
        self.responses = self.useFixture(fixture.Fixture())
        self.endpoint = 'http://localhost:9311'
        self.project_id = '1234567'

        self.entity = entity
        self.entity_id = entity_id
        self.entity_base = self.endpoint + "/v1/" + self.entity
        self.entity_href = self.entity_base + "/" + self.entity_id
        self.entity_payload_href = self.entity_href + "/payload"

        self.client = client.Client(endpoint=self.endpoint,
                                    project_id=self.project_id)
