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
from testtools import testcase
from functionaltests.client import base
from functionaltests.client.v1.behaviors import secret_behaviors
from functionaltests import utils

secret_create_defaults_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ=="
}

secret_create_nones_data = {
    "name": None,
    "expiration": None,
    "algorithm": None,
    "bit_length": None,
    "mode": None,
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}


@utils.parameterized_test_case
class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.barbicanclient)

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_create_secret_defaults(self):
        """Creates a secret with default values"""
        test_model = self.behaviors.create_secret(secret_create_defaults_data)

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

    @testcase.attr('positive')
    def test_secret_create_defaults_no_expiration(self):
        """Covers creating a secret without an expiration."""
        test_model = self.behaviors.create_secret(secret_create_defaults_data)
        test_model.expiration = None

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

    @testcase.attr('positive')
    def test_secret_delete_defaults(self):
        """Covers deleting a secret."""
        test_model = self.behaviors.create_secret(secret_create_defaults_data)

        secret_ref = self.behaviors.store_secret(test_model)

        del_response = self.behaviors.delete_secret(secret_ref)
        self.assertIsNone(del_response)

    @testcase.attr('positive')
    def test_secret_delete_minimal_secret_w_no_metadata(self):
        """Covers deleting a secret with nones data."""
        test_model = self.behaviors.create_secret(secret_create_nones_data)

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        del_resp = self.behaviors.delete_secret(secret_ref)
        self.assertIsNone(del_resp)

    @testcase.attr('positive')
    def test_secret_get_defaults_payload(self):
        """Covers getting a secret's payload data."""
        test_model = self.behaviors.create_secret(secret_create_defaults_data)
        secret_ref = self.behaviors.store_secret(test_model)

        get_resp = self.behaviors.get_secret(
            secret_ref
            )
        self.assertEqual(test_model.payload, get_resp.payload)

    @testcase.attr('positive')
    def test_secrets_get_defaults_multiple_secrets(self):
        """Covers getting a list of secrets.

        Creates 11 secrets then returns a list of 5 secrets
        """
        limit = 5
        offset = 5
        total = 10

        for i in range(0, total + 1):
            test_model = self.behaviors.create_secret(
                secret_create_defaults_data)
            self.behaviors.store_secret(test_model)

        secret_list = self.behaviors.get_secrets(limit=limit,
                                                 offset=offset)
        self.assertEqual(len(secret_list), limit)
