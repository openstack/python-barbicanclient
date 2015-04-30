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
import six

from barbicanclient.tests import keystone_client_fixtures
from barbicanclient.tests import test_client
from barbicanclient.barbican import Barbican


class WhenTestingBarbicanCLI(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('barbican')
        self.captured_stdout = six.StringIO()
        self.captured_stderr = six.StringIO()
        self.barbican = Barbican(
            stdout=self.captured_stdout,
            stderr=self.captured_stderr
        )
        self.parser = self.barbican.build_option_parser('desc', 'vers')

    def assert_client_raises(self, args, message):
        argv, remainder = self.parser.parse_known_args(args.split())
        e = self.assertRaises(
            Exception, self.barbican.create_client, argv
        )
        self.assertIn(message, str(e))

    def create_and_assert_client(self, args):
        argv, remainder = self.parser.parse_known_args(args.split())

        client = self.barbican.create_client(argv)
        self.assertIsNotNone(client)
        return client

    def test_should_show_usage_with_help_flag(self):
        e = self.assertRaises(SystemExit, self.parser.parse_known_args, ['-h'])
        self.assertEqual(0, e.code)
        self.assertIn('usage', self.captured_stdout.getvalue())

    def test_should_show_usage_with_no_args(self):
        exit_code = self.barbican.run([])
        self.assertEquals(1, exit_code)
        self.assertIn('usage', self.captured_stderr.getvalue())

    def test_should_error_if_noauth_and_authurl_both_specified(self):
        args = "--no-auth --os-auth-url http://localhost:5000/v3"
        message = (
            'ERROR: argument --os-auth-url/-A: not allowed with '
            'argument --no-auth/-N'
        )
        self.assert_client_raises(args, message)

    def _expect_error_with_invalid_noauth_args(self, args):
        expected_err_msg = (
            'ERROR: please specify --endpoint '
            'and --os-project-id (or --os-tenant-id)'
        )
        self.assert_client_raises(args, expected_err_msg)

    def test_should_error_if_noauth_and_missing_endpoint_tenantid_args(self):
        self._expect_error_with_invalid_noauth_args("--no-auth secret list")
        self._expect_error_with_invalid_noauth_args(
            "--no-auth --endpoint http://xyz secret list")
        self._expect_error_with_invalid_noauth_args(
            "--no-auth --os-tenant-id 123 secret list")
        self._expect_error_with_invalid_noauth_args(
            "--no-auth --os-project-id 123 secret list")

    def test_should_succeed_if_noauth_with_valid_args_specified(self):
        args = (
            '--no-auth --endpoint {0} --os-tenant-id {1}'
            'secret list'.format(self.endpoint, self.project_id)
        )
        list_secrets_url = '{0}/v1/secrets'.format(self.endpoint)
        self.responses.get(list_secrets_url, json={"secrets": [], "total": 0})
        client = self.create_and_assert_client(args)
        secret_list = client.secrets.list()
        self.assertTrue(self.responses._adapter.called)
        self.assertEqual(1, self.responses._adapter.call_count)
        self.assertEqual([], secret_list)

    def test_should_error_if_required_keystone_auth_arguments_are_missing(
            self):
        expected_error_msg = (
            'ERROR: please specify the following --os-project-id or'
            ' (--os-project-name and --os-project-domain-name) or '
            ' (--os-project-name and --os-project-domain-id)'
        )
        self.assert_client_raises(
            '--os-auth-url http://localhost:35357/v2.0 secret list',
            expected_error_msg)
        self.assert_client_raises(
            '--os-auth-url http://localhost:35357/v2.0 --os-username barbican '
            '--os-password barbican secret list',
            expected_error_msg
        )


class TestBarbicanWithKeystonePasswordAuth(
        keystone_client_fixtures.KeystoneClientFixture):

    def setUp(self):
        super(TestBarbicanWithKeystonePasswordAuth, self).setUp()

        self.test_arguments = {
            '--os-username': 'some_user',
            '--os-password': 'some_pass',
        }


class TestBarbicanWithKeystoneTokenAuth(
        keystone_client_fixtures.KeystoneClientFixture):

    def setUp(self):
        super(TestBarbicanWithKeystoneTokenAuth, self).setUp()

        self.test_arguments = {
            '--os-auth-token': 'some_token',
            '--os-project-id': 'some_project_id',
        }
