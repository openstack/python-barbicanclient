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
from functionaltests.cli.v1.behaviors.secret_behaviors import SecretBehaviors
from functionaltests.common import keys
from functionaltests import utils
from testtools import testcase


@utils.parameterized_test_case
class SecretTestCase(CmdLineTestCase):

    def setUp(self):
        super(SecretTestCase, self).setUp()
        self.secret_behaviors = SecretBehaviors()
        self.expected_payload = "Top secret payload for secret smoke tests"
        self.payload_content_type = "text/plain"

    def tearDown(self):
        super(SecretTestCase, self).tearDown()
        self.secret_behaviors.delete_all_created_secrets()

    @utils.parameterized_dataset({
        'symmetric': ['symmetric',
                      'aes',
                      '128',
                      (b'\x00\x01\x02\x03\x04\x05\x06\x07'
                       b'\x00\x01\x02\x03\x04\x05\x06\x07')],
        'private': ['private',
                    'rsa',
                    '2048',
                    keys.get_private_key_pem()],
        'public': ['public',
                   'rsa',
                   '2048',
                   keys.get_public_key_pem()],
        'certificate': ['certificate',
                        'rsa',
                        '2048',
                        keys.get_certificate_pem()],
        'opaque': ['opaque',
                   None,
                   None,
                   (b'\x00\x01\x02\x03\x04\x05\x06\x07')],
        'passphrase': ['passphrase',
                       None,
                       None,
                       keys.get_passphrase_txt()],
    })
    @testcase.attr('positive')
    def test_secret_store_with_secret_type(self, secret_type, algorithm,
                                           bit_length, secret):
        payload = secret
        secret_argv = ['--secret-type', secret_type]
        if algorithm:
            secret_argv.extend(['--algorithm', algorithm])
        if bit_length:
            secret_argv.extend(['--bit-length', bit_length])
        secret_href = self.secret_behaviors.store_secret(payload, secret_argv)
        self.assertIsNotNone(secret_href)

        secret = self.secret_behaviors.get_secret(secret_href)
        self.assertEqual(secret_href, secret['Secret href'])

    @testcase.attr('positive')
    def test_secret_store(self):
        secret_href = self.secret_behaviors.store_secret()
        self.assertIsNotNone(secret_href)

        secret = self.secret_behaviors.get_secret(secret_href)
        self.assertEqual(secret_href, secret['Secret href'])

    @testcase.attr('positive')
    def test_secret_update(self):
        secret_href = self.secret_behaviors.store_secret(
            payload=None)

        payload = 'time for an ice cold!!!'
        self.assertIsNotNone(secret_href)
        self.secret_behaviors.update_secret(secret_href,
                                            payload)

        payload_update = self.secret_behaviors.get_secret_payload(secret_href)
        self.assertEqual(payload, payload_update)

    @testcase.attr('positive')
    def test_secret_list(self):
        secrets_to_create = 10
        for _ in range(secrets_to_create):
            self.secret_behaviors.store_secret()
        secret_list = self.secret_behaviors.list_secrets()
        self.assertGreaterEqual(len(secret_list), secrets_to_create)

    @testcase.attr('positive')
    def test_secret_delete(self):
        secret_href = self.secret_behaviors.store_secret()
        self.secret_behaviors.delete_secret(secret_href)

        secret = self.secret_behaviors.get_secret(secret_href)
        self.assertEqual(0, len(secret))

    @testcase.attr('positive')
    def test_secret_get(self):
        secret_href = self.secret_behaviors.store_secret()
        secret = self.secret_behaviors.get_secret(secret_href)
        self.assertIsNotNone(secret)

    @testcase.attr('positive')
    def test_secret_get_payload(self):
        secret_href = self.secret_behaviors.store_secret(
            payload=self.expected_payload)
        payload = self.secret_behaviors.get_secret_payload(secret_href)
        self.assertEqual(payload, self.expected_payload)

    @testcase.attr('positive')
    def test_secret_get_raw_payload(self):
        secret_href = self.secret_behaviors.store_secret(
            payload=self.expected_payload)
        payload = self.secret_behaviors.get_secret_payload(secret_href,
                                                           raw=True)
        self.assertEqual(payload, self.expected_payload)

    @testcase.attr('positive')
    def test_secret_file_parameter_read(self):
        secret_href = self.secret_behaviors.store_secret(
            payload=self.expected_payload)
        self.secret_behaviors.get_secret_file(secret_href=secret_href)
        payload = self.secret_behaviors.read_secret_test_file()
        self.assertEqual(payload, self.expected_payload)

    @testcase.attr('positive')
    def test_secret_file_parameter_write(self):
        self.secret_behaviors.write_secret_test_file(
            payload=self.expected_payload)
        secret_href = self.secret_behaviors.store_secret_file()
        payload = self.secret_behaviors.get_secret_payload(secret_href)
        self.assertEqual(payload, self.expected_payload)
