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

from functionaltests.client import base
from functionaltests.common import cleanup
from functionaltests.common import keys
from functionaltests import utils
from testtools import testcase

secret_create_defaults_data = {
    "name": "AES key",
    "expiration": "2030-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": b"gF6+lLoF3ohA9aPRpt+6bQ=="
}

secret_create_nones_data = {
    "name": None,
    "expiration": None,
    "algorithm": None,
    "bit_length": None,
    "mode": None,
    "payload": b"gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}


@utils.parameterized_test_case
class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.cleanup = cleanup.CleanUp(self.barbicanclient)

    def tearDown(self):
        self.cleanup.delete_all_entities()
        super(SecretsTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_create_secret_defaults(self):
        """Creates a secret with default values"""
        secret = self.barbicanclient.secrets.create(
            **secret_create_defaults_data)

        secret_ref = self.cleanup.add_entity(secret)
        self.assertIsNotNone(secret_ref)

    @testcase.attr('positive')
    @utils.parameterized_dataset({
        'symmetric': ['symmetric',
                      'aes',
                      128,
                      (b'\x00\x01\x02\x03\x04\x05\x06\x07'
                       b'\x00\x01\x02\x03\x04\x05\x06\x07')],
        'private': ['private',
                    'rsa',
                    2048,
                    keys.get_private_key_pem()],
        'public': ['public',
                   'rsa',
                   2048,
                   keys.get_public_key_pem()],
        'certificate': ['certificate',
                        'rsa',
                        2048,
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
    def test_create_secret_with_type(self, secret_type, algorithm, bit_length,
                                     secret):
        """Creates a secret with default values"""
        secret_data = secret_create_defaults_data
        secret_data['secret_type'] = secret_type
        secret_data['algorithm'] = algorithm
        secret_data['bit_length'] = bit_length
        # payload should not be encoded.
        secret_data['payload'] = secret
        secret = self.barbicanclient.secrets.create(
            **secret_create_defaults_data)

        secret_ref = self.cleanup.add_entity(secret)
        self.assertIsNotNone(secret_ref)

    @testcase.attr('positive')
    def test_secret_create_defaults_no_expiration(self):
        """Covers creating a secret without an expiration."""
        secret = self.barbicanclient.secrets.create(
            **secret_create_defaults_data)
        secret.expiration = None

        secret_ref = self.cleanup.add_entity(secret)
        self.assertIsNotNone(secret_ref)

    @testcase.attr('positive')
    def test_secret_delete_defaults(self):
        """Covers deleting a secret."""
        secret = self.barbicanclient.secrets.create(
            **secret_create_defaults_data)

        secret_ref = secret.store()

        del_response = self.barbicanclient.secrets.delete(secret_ref)
        self.assertIsNone(del_response)

    @testcase.attr('positive')
    def test_secret_delete_minimal_secret_w_no_metadata(self):
        """Covers deleting a secret with nones data."""
        secret = self.barbicanclient.secrets.create(
            **secret_create_nones_data)

        secret_ref = secret.store()
        self.assertIsNotNone(secret_ref)

        del_resp = self.barbicanclient.secrets.delete(secret_ref)
        self.assertIsNone(del_resp)

    @testcase.attr('positive')
    def test_secret_get_defaults_payload(self):
        """Covers getting a secret's payload data."""
        secret = self.barbicanclient.secrets.create(
            **secret_create_defaults_data)
        secret_ref = self.cleanup.add_entity(secret)

        secret_resp = self.barbicanclient.secrets.get(secret_ref)
        self.assertEqual(secret.payload, secret_resp.payload)

    @testcase.attr('positive')
    def test_secrets_get_defaults_multiple_secrets(self):
        """Covers getting a list of secrets.

        Creates 11 secrets then returns a list of 5 secrets
        """
        limit = 5
        offset = 5
        total = 10

        for i in range(0, total + 1):
            secret = self.barbicanclient.secrets.create(
                **secret_create_defaults_data)
            self.cleanup.add_entity(secret)

        secret_list = self.barbicanclient.secrets.list(limit=limit,
                                                       offset=offset)

        self.assertEqual(limit, len(secret_list))
