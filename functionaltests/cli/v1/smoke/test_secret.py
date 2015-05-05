# Copyright (c) 2015 Rackspace, Inc.
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

from functionaltests.cli.base import CmdLineTestCase
from testtools import testcase


class SecretTestCase(CmdLineTestCase):

    def setUp(self):
        super(SecretTestCase, self).setUp()
        self.secret_hrefs_to_delete = []
        self.expected_payload = 'This is a top secret payload'

    def tearDown(self):
        super(SecretTestCase, self).tearDown()
        for href in self.secret_hrefs_to_delete:
            self._delete_secret(href)

    @testcase.attr('positive')
    def test_secret_store(self):
        secret_href = self._store_secret()
        self.assertIsNotNone(secret_href)

        secret = self._get_secret(secret_href)
        self.assertEqual(secret_href, secret['Secret href'])

    @testcase.attr('positive')
    def test_secret_list(self):
        secrets_to_create = 10
        for _ in range(secrets_to_create):
            self._store_secret()
        secret_list = self._list_secrets()
        self.assertGreaterEqual(len(secret_list), secrets_to_create)

    @testcase.attr('positive')
    def test_secret_delete(self):
        secret_href = self._store_secret()
        self._delete_secret(secret_href)

        secret = self._get_secret(secret_href)
        self.assertEqual(0, len(secret))

    @testcase.attr('positive')
    def test_secret_get(self):
        secret_href = self._store_secret()
        secret = self._get_secret(secret_href)
        self.assertIsNotNone(secret)

    @testcase.attr('positive')
    def test_secret_get_payload(self):
        secret_href = self._store_secret()
        payload = self._get_secret_payload(secret_href)
        self.assertEqual(payload, self.expected_payload)

    @testcase.attr('positive')
    def test_secret_get_raw_payload(self):
        secret_href = self._store_secret()
        payload = self._get_secret_payload(secret_href, raw=True)
        self.assertEqual(payload, self.expected_payload)

    def _delete_secret(self, secret_href):
        """ Delete a secret

        :param secret_href the href to the secret to delete
        """
        argv = ['secret', 'delete']
        self.add_auth_and_endpoint(argv)
        argv.extend([secret_href])

        stdout, stderr = self.issue_barbican_command(argv)
        self.assertEqual(0, len(stdout))
        self.assertEqual(0, len(stderr))

        self.secret_hrefs_to_delete.remove(secret_href)

    def _store_secret(self):
        """ Store (aka create) a secret

        :return: the href to the newly created secret
        """
        argv = ['secret', 'store']
        self.add_auth_and_endpoint(argv)
        argv.extend(['--payload', self.expected_payload])

        stdout, stderr = self.issue_barbican_command(argv)
        self.assertIsNotNone(stdout, 'no secret store string')
        self.assertGreater(len(stdout), 0, 'invalid secret store length')

        secret_data = self._prettytable_to_secret(stdout)
        self.assertIsNotNone(secret_data)

        secret_href = secret_data['Secret href']
        self.secret_hrefs_to_delete.append(secret_href)
        return secret_href

    def _get_secret(self, secret_href):
        """ Get a secret

        :param: the href to a secret
        :return dict of secret values, or an empty dict if the secret
        is not found.
        """
        argv = ['secret', 'get']
        self.add_auth_and_endpoint(argv)
        argv.extend([secret_href])

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        self.assertIsNotNone(stdout, 'no secret get string')
        self.assertGreater(len(stdout), 0, 'invalid secret get length')

        secret_data = self._prettytable_to_secret(stdout)
        return secret_data

    def _get_secret_payload(self, secret_href, raw=False):
        """ Get a secret

        :param: the href to a secret
        :param raw if True then add "-f value" to get raw payload (ie not
        within a PrettyTable).  If False then omit -f.
        :return string representing the secret payload.
        """
        argv = ['secret', 'get']
        self.add_auth_and_endpoint(argv)
        argv.extend([secret_href])
        argv.extend(['--payload'])
        if raw:
            argv.extend(['-f', 'value'])

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        self.assertIsNotNone(stdout, 'no secret get payload string')
        self.assertGreater(len(stdout), 0, 'invalid secret get payload length')

        if raw:
            secret = stdout.rstrip()
        else:
            secret_data = self._prettytable_to_secret(stdout)
            secret = secret_data['Payload']

        return secret

    def _list_secrets(self):
        """ List secrets

        :return: a list of secrets
        """
        argv = ['secret', 'list']

        self.add_auth_and_endpoint(argv)
        stdout, stderr = self.issue_barbican_command(argv)
        self.assertIsNotNone(stdout, 'no secret list string')
        self.assertGreater(len(stdout), 0, 'invalid secret list length')

        secret_list = self._prettytable_to_secret_list(stdout)
        self.assertIsNotNone(secret_list)

        return secret_list
