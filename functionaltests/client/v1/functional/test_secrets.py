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

import base64

from functionaltests.client import base
from functionaltests.client.v1.behaviors import secret_behaviors
from functionaltests import utils
from testtools import testcase

secret_create_defaults_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
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

secret_create_emptystrings_data = {
    "name": '',
    "expiration": '',
    "algorithm": '',
    "bit_length": '',
    "mode": '',
    "payload": '',
    "payload_content_type": '',
    "payload_content_encoding": '',
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
    def test_secret_create_defaults_check_content_types(self):
        """Check that set content-type attribute is retained in metadata."""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        resp = self.behaviors.get_secret(secret_ref)
        content_types = resp.content_types
        self.assertIsNotNone(content_types)
        self.assertIn('default', content_types)
        self.assertEqual(content_types['default'],
                         test_model.payload_content_type)

    @testcase.attr('positive')
    def test_secret_create_defaults_non_standard_algorithm(self):
        """Create a secret with a non standard algorithm.

         Currently the client will accept any string for the algorithm.
         """
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.algorithm = "not-an-algorithm"

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertEqual(get_resp.algorithm, test_model.algorithm)

    @testcase.attr('positive')
    def test_secret_create_defaults_non_standard_mode(self):
        """Create a secret with a non standard mode.

        Currently the client will accept any string for the mode.
        """
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.mode = 'not-a-mode'

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertEqual(get_resp.mode, test_model.mode)

    @utils.parameterized_dataset({
        'alphanumeric': ['1f34ds'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'len_255': [base.TestCase.max_sized_field],
        'empty': [''],
        'null': [None]
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_name(self, name):
        """Covers cases of creating secrets with valid names."""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.name = name

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertEqual(get_resp.name, test_model.name)

    @utils.parameterized_dataset({
        'aes': ['aes']
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_algorithms(self, algorithm):
        """Creates secrets with various valid algorithms."""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.algorithm = algorithm

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertEqual(get_resp.algorithm, test_model.algorithm)

    @utils.parameterized_dataset({
        '512': [512],
        'sixteen': [16],
        'fifteen': [15],
        'eight': [8],
        'seven': [7],
        'one': [1],
        'none': [None]
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_bit_length(self, bit_length):
        """Covers cases of creating secrets with valid bit lengths."""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.bit_length = bit_length

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertEqual(get_resp.bit_length, test_model.bit_length)

    @utils.parameterized_dataset({
        'cbc': ['cbc']
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_mode(self, mode):
        """Covers cases of creating secrets with valid modes."""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.mode = mode

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertEqual(get_resp.mode, test_model.mode)

    @utils.parameterized_dataset({
        'text_content_type_none_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': None},

        'utf8_text_content_type_none_encoding': {
            'payload_content_type': 'text/plain; charset=utf-8',
            'payload_content_encoding': None},

        'no_space_utf8_text_content_type_none_encoding': {
            'payload_content_type': 'text/plain;charset=utf-8',
            'payload_content_encoding': None},

        'octet_content_type_base64_encoding': {
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'base64'}
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_types_and_encoding(
            self,
            payload_content_type,
            payload_content_encoding):
        """Creates secrets with various content types and encodings."""
        test_model = self.behaviors.create_secret(secret_create_defaults_data)
        test_model.payload_content_encoding = payload_content_encoding
        test_model.payload_content_type = payload_content_type

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(
            secret_ref,
            payload_content_type=test_model.payload_content_type)

        if test_model.payload_content_encoding == 'base64':
            self.assertEqual(test_model.payload,
                             str(base64.b64encode(get_resp.payload)))
        else:
            self.assertEqual(test_model.payload, str(get_resp.payload))

    @utils.parameterized_dataset({
        'max_payload_string': [base.TestCase.max_sized_payload]
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_payload(self, payload):
        """Create secrets with a various valid payloads."""
        test_model = self.behaviors.create_secret(secret_create_defaults_data)
        test_model.payload = payload

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertEqual(test_model.payload,
                         str(base64.b64encode(get_resp.payload)))

    @utils.parameterized_dataset({
        'negative_five_long_expire': {
            'timezone': '-05:00',
            'days': 5},

        'positive_five_long_expire': {
            'timezone': '+05:00',
            'days': 5},

        'negative_one_short_expire': {
            'timezone': '-01',
            'days': 1},

        'positive_one_short_expire': {
            'timezone': '+01',
            'days': 1}
    })
    @testcase.attr('positive')
    def test_secret_create_defaults_valid_expiration(self, **kwargs):
        """Create secrets with a various valid expiration data."""

        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.expiration = timestamp

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertIsNotNone(get_resp)
        self.assertEqual(get_resp.name, test_model.name)

    @utils.parameterized_dataset({
        'alphanumeric': ['1f34ds'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'len_255': [str(bytearray().zfill(255))],
        'empty': [''],
        'null': [None]
    })
    @testcase.attr('positive')
    def test_secret_get_defaults_metadata_w_valid_name(self, name):
        """Covers getting and checking a secret's metadata."""
        test_model = self.behaviors.create_secret(secret_create_defaults_data)
        test_model.name = name

        secret_ref = self.behaviors.store_secret(test_model)
        self.assertIsNotNone(secret_ref)

        get_resp = self.behaviors.get_secret(secret_ref)
        self.assertEqual(get_resp.status, "ACTIVE")
        self.assertEqual(get_resp.name, name)
        self.assertEqual(get_resp.mode, test_model.mode)
        self.assertEqual(get_resp.algorithm, test_model.algorithm)
        self.assertEqual(get_resp.bit_length, test_model.bit_length)
