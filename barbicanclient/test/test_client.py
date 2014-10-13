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
import testtools

from barbicanclient import client


class TestClient(testtools.TestCase):

    def setUp(self):
        super(TestClient, self).setUp()
        self.endpoint = 'http://localhost:9311'
        self.project_id = 'project_id'
        self.client = client.Client(endpoint=self.endpoint,
                                    project_id=self.project_id)


class WhenTestingClientInit(TestClient):

    def _get_fake_session(self):
        sess = mock.MagicMock()
        sess.get_endpoint.return_value = self.endpoint
        return sess

    def test_can_be_used_without_a_session(self):
        c = client.Client(endpoint=self.endpoint,
                          project_id=self.project_id)
        self.assertIsNotNone(c._session)

    def test_api_version_is_appended_to_endpoint(self):
        c = client.Client(endpoint=self.endpoint,
                          project_id=self.project_id)
        self.assertEqual(c._base_url, 'http://localhost:9311/v1')

    def test_default_headers_are_empty(self):
        c = client.Client(session=self._get_fake_session())
        self.assertIsInstance(c._default_headers, dict)
        self.assertFalse(bool(c._default_headers))

    def test_project_id_is_added_to_default_headers(self):
        c = client.Client(endpoint=self.endpoint,
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
        c = client.Client(endpoint=self.endpoint + '/',
                          project_id=self.project_id)
        self.assertEqual(c._barbican_endpoint, self.endpoint)

    def test_base_url_starts_with_endpoint_url(self):
        c = client.Client(endpoint=self.endpoint, project_id=self.project_id)
        self.assertTrue(c._base_url.startswith(self.endpoint))

    def test_base_url_ends_with_default_api_version(self):
        c = client.Client(endpoint=self.endpoint, project_id=self.project_id)
        self.assertTrue(c._base_url.endswith(client._DEFAULT_API_VERSION))

    def test_gets_endpoint_from_keystone_session(self):
        c = client.Client(session=self._get_fake_session())
        self.assertEqual(c._barbican_endpoint, self.endpoint)


class TestClientWithSession(testtools.TestCase):

    def setUp(self):
        super(TestClientWithSession, self).setUp()
        self.endpoint = 'http://localhost:9311'

    def _get_fake_session_with_status_code(self, status_code):
        resp = mock.MagicMock()
        resp.status_code = status_code
        sess = mock.MagicMock()
        sess.get.return_value = resp
        sess.post.return_value = resp
        sess.delete.return_value = resp
        sess.get_endpoint.return_value = self.endpoint
        return sess


class WhenTestingClientPost(TestClientWithSession):

    def setUp(self):
        super(WhenTestingClientPost, self).setUp()
        self.session = self._get_fake_session_with_status_code(201)
        self.client = client.Client(session=self.session)

    def test_post_normalizes_url_with_traling_slash(self):
        self.client._post(path='secrets', data={'test_data': 'test'})
        args, kwargs = self.session.post.call_args
        url = args[0]
        self.assertTrue(url.endswith('/'))

    def test_post_includes_content_type_header_of_application_json(self):
        self.client._post(path='secrets', data={'test_data': 'test'})
        args, kwargs = self.session.post.call_args
        headers = kwargs.get('headers')
        self.assertIn('Content-Type', headers.keys())
        self.assertEqual(headers['Content-Type'], 'application/json')

    def test_post_includes_default_headers(self):
        self.client._default_headers = {'Test-Default-Header': 'test'}
        self.client._post(path='secrets', data={'test_data': 'test'})
        args, kwargs = self.session.post.call_args
        headers = kwargs.get('headers')
        self.assertIn('Test-Default-Header', headers.keys())

    def test_post_checks_status_code(self):
        self.client._check_status_code = mock.MagicMock()
        self.client._post(path='secrets', data={'test_data': 'test'})
        resp = self.session.post()
        self.client._check_status_code.assert_called_with(resp)


class WhenTestingClientGet(TestClientWithSession):

    def setUp(self):
        super(WhenTestingClientGet, self).setUp()
        self.session = self._get_fake_session_with_status_code(200)
        self.client = client.Client(session=self.session)
        self.headers = dict()
        self.href = 'http://test_href'

    def test_get_uses_href_as_is(self):
        self.client._get(self.href)
        args, kwargs = self.session.get.call_args
        url = args[0]
        self.assertEqual(url, self.href)

    def test_get_passes_params(self):
        params = object()
        self.client._get(self.href, params=params)
        args, kwargs = self.session.get.call_args
        passed_params = kwargs.get('params')
        self.assertIs(params, passed_params)

    def test_get_includes_accept_header_of_application_json(self):
        self.client._get(self.href)
        args, kwargs = self.session.get.call_args
        headers = kwargs.get('headers')
        self.assertIn('Accept', headers.keys())
        self.assertEqual(headers['Accept'], 'application/json')

    def test_get_includes_default_headers(self):
        self.client._default_headers = {'Test-Default-Header': 'test'}
        self.client._get(self.href)
        args, kwargs = self.session.get.call_args
        headers = kwargs.get('headers')
        self.assertIn('Test-Default-Header', headers.keys())

    def test_get_checks_status_code(self):
        self.client._check_status_code = mock.MagicMock()
        self.client._get(self.href)
        resp = self.session.get()
        self.client._check_status_code.assert_called_with(resp)

    def test_get_raw_uses_href_as_is(self):
        self.client._get_raw(self.href, self.headers)
        args, kwargs = self.session.get.call_args
        url = args[0]
        self.assertEqual(url, self.href)

    def test_get_raw_passes_headers(self):
        self.client._get_raw(self.href, self.headers)
        args, kwargs = self.session.get.call_args
        headers = kwargs.get('headers')
        self.assertIs(headers, self.headers)

    def test_get_raw_includes_default_headers(self):
        self.client._default_headers = {'Test-Default-Header': 'test'}
        self.client._get_raw(self.href, self.headers)
        self.assertIn('Test-Default-Header', self.headers.keys())

    def test_get_raw_checks_status_code(self):
        self.client._check_status_code = mock.MagicMock()
        self.client._get_raw(self.href, self.headers)
        resp = self.session.get()
        self.client._check_status_code.assert_called_with(resp)


class WhenTestingClientDelete(TestClientWithSession):

    def setUp(self):
        super(WhenTestingClientDelete, self).setUp()
        self.session = self._get_fake_session_with_status_code(200)
        self.client = client.Client(session=self.session)
        self.href = 'http://test_href'

    def test_delete_uses_href_as_is(self):
        self.client._delete(self.href)
        args, kwargs = self.session.delete.call_args
        url = args[0]
        self.assertEqual(url, self.href)

    def test_delete_passes_json(self):
        json = '{"test": "test"}'
        self.client._delete(self.href, json=json)
        args, kwargs = self.session.delete.call_args
        passed_json = kwargs.get('json')
        self.assertEqual(passed_json, json)

    def test_delete_includes_default_headers(self):
        self.client._default_headers = {'Test-Default-Header': 'test'}
        self.client._delete(self.href)
        args, kwargs = self.session.delete.call_args
        headers = kwargs.get('headers')
        self.assertIn('Test-Default-Header', headers.keys())

    def test_delete_checks_status_code(self):
        self.client._check_status_code = mock.MagicMock()
        self.client._delete(self.href)
        resp = self.session.get()
        self.client._check_status_code.assert_called_with(resp)


class WhenTestingCheckStatusCodes(TestClient):

    def test_raises_http_auth_error_for_401_response(self):
        resp = mock.MagicMock()
        resp.status_code = 401
        self.assertRaises(client.HTTPAuthError, self.client._check_status_code,
                          resp)

    def test_raises_http_server_error_for_500_response(self):
        resp = mock.MagicMock()
        resp.status_code = 500
        self.assertRaises(client.HTTPServerError,
                          self.client._check_status_code, resp)

    def test_raises_http_client_error_for_400_response(self):
        resp = mock.MagicMock()
        resp.status_code = 400
        self.assertRaises(client.HTTPClientError,
                          self.client._check_status_code, resp)


class WhenTestingGetErrorMessage(TestClient):

    def test_gets_error_message_from_title_in_json(self):
        resp = mock.MagicMock()
        resp.json.return_value = {'title': 'test_text'}
        msg = self.client._get_error_message(resp)
        self.assertEqual(msg, 'test_text')

    def test_gets_error_message_from_content_when_no_json(self):
        resp = mock.MagicMock()
        resp.json.side_effect = ValueError()
        resp.content = content = 'content'
        msg = self.client._get_error_message(resp)
        self.assertEqual(msg, content)


class BaseEntityResource(testtools.TestCase):

    # TODO: The compatibility of unittest between versions is horrible
    # Reported as https://bugs.launchpad.net/testtools/+bug/1373139
    if hasattr(testtools.TestCase, 'assertItemsEqual'):
        # If this function is available, do nothing (PY27)
        pass
    elif hasattr(testtools.TestCase, 'assertCountEqual'):
        # If this function is available, alias it (PY32+)
        assertItemsEqual = testtools.TestCase.assertCountEqual
    else:
        # If neither is available, make our own version (PY26, PY30-31)
        def assertItemsEqual(self, expected_seq, actual_seq, msg=None):
            first_seq, second_seq = list(expected_seq), list(actual_seq)
            differences = []
            for item in first_seq:
                if item not in second_seq:
                    differences.append(item)

            for item in second_seq:
                if item not in first_seq:
                    differences.append(item)

            if differences:
                if not msg:
                    msg = "Items differ: {0}".format(differences)
                self.fail(msg)
            if len(first_seq) != len(second_seq):
                if not msg:
                    msg = "Size of collection differs: {0} != {1}".format(
                        len(first_seq), len(second_seq)
                    )
                self.fail(msg)

    def _setUp(self, entity):
        super(BaseEntityResource, self).setUp()
        self.endpoint = 'http://localhost:9311'
        self.project_id = '1234567'

        self.entity = entity
        self.entity_base = self.endpoint + "/" + self.entity + "/"
        self.entity_href = self.entity_base + \
            'abcd1234-eabc-5678-9abc-abcdef012345'

        self.api = mock.MagicMock()
        self.api._base_url = self.endpoint
