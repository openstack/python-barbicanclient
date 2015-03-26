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
import sys

from functionaltests.client import base
from functionaltests.client.v1.behaviors import secret_behaviors
from functionaltests import utils
from testtools import testcase

from barbicanclient import exceptions

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
        self.assertEqual('application/octet-stream', content_types['default'])

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

    @testcase.attr('negative')
    def test_secret_delete_doesnt_exist(self):
        """Deletes a non-existent secret.

        This delete uses a reference with an invalid UUID format
        """
        url = self.behaviors.base_url + '/secrets/notauuid'

        e = self.assertRaises(ValueError, self.behaviors.delete_secret,
                              url)

        self.assertEqual(e.message, 'Secret incorrectly specified.')

    @testcase.attr('negative')
    def test_secret_delete_doesnt_exist_valid_uuid_format(self):
        """Deletes a non-existent secret.

        This delete has a valid UUID format but there is no secret
        associated with this UUID
        """
        uuid = 'de20ad54-85b4-421b-adb2-eb7b9e546013'
        url = self.behaviors.base_url + '/secrets/' + uuid

        e = self.assertRaises(Exception, self.behaviors.delete_secret,
                              url)

        self.assertEqual(e.http_status, 404)

    @testcase.attr('negative')
    def test_secret_create_nones_content_type(self):
        """Create secret with valid content type but no payload.

        Secret will not create due to None in the payload even if content
        type is valid.
        """
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.payload = None

        self.assertRaises(
            exceptions.PayloadException,
            self.behaviors.store_secret,
            test_model
        )

    @testcase.attr('negative')
    def test_secret_create_nones(self):
        """Cover case of posting with all nones in the Secret object."""
        test_model = self.behaviors.create_secret(
            secret_create_nones_data)
        test_model.payload = None
        test_model.payload_content_encoding = None
        test_model.payload_content_type = None

        self.assertRaises(
            exceptions.PayloadException,
            self.behaviors.store_secret,
            test_model
        )

    @testcase.attr('negative')
    def test_secret_get_secret_doesnt_exist(self):
        """GET an invalid secret ref.

        Will get value error secret incorrectly specified since "notauuid"
        is not a properly formatted uuid.
        """
        url = self.behaviors.base_url + '/secrets/notauuid'

        e = self.assertRaises(ValueError, self.behaviors.get_secret,
                              url)

        self.assertIn("Secret incorrectly specified", e.message)

    @testcase.attr('negative')
    def test_secret_create_defaults_expiration_passed(self):
        """Create a secret with an expiration that has already passed.

        Returns a 400.
        """
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.expiration = '2000-01-10T14:58:52.546795'

        e = self.assertRaises(Exception, self.behaviors.store_secret,
                              test_model)
        self.assertEqual(e.http_status, 400)

    @testcase.attr('negative')
    def test_secret_create_emptystrings(self):
        """Secret create with empty Strings for all attributes.

        Fails with a value error, Payload incorrectly specified.
        """
        test_model = self.behaviors.create_secret(
            secret_create_emptystrings_data)

        self.assertRaises(
            exceptions.PayloadException,
            self.behaviors.store_secret,
            test_model
        )

    @testcase.attr('negative')
    def test_secret_create_defaults_oversized_payload(self):
        """Create a secret with a payload that is larger than the allowed size.

        Should return a 413 if the secret size is greater than the
        maximum allowed size.
        """
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.payload = str(self.oversized_payload)

        e = self.assertRaises(Exception, self.behaviors.store_secret,
                              test_model)
        self.assertEqual(e.http_status, 413)

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
        'int': [400]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_name(self, name):
        """Create secrets with various invalid names.

        Should return 400.
        """
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.name = name

        e = self.assertRaises(Exception, self.behaviors.store_secret,
                              test_model)

        self.assertEqual(e.http_status, 400)

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
        'int': [400]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_algorithms(self, algorithm):
        """Creates secrets with various invalid algorithms."""

        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.algorithm = algorithm

        # We are currently testing for exception with http_code
        # launchpad bug 1431514 will address the change to this functionality
        e = self.assertRaises(Exception, self.behaviors.store_secret,
                              test_model)

        self.assertEqual(e.http_status, 400)

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
        'str_type': ['not-an-int'],
        'empty': [''],
        'blank': [' '],
        'negative_maxint': [-sys.maxint],
        'negative_one': [-1],
        'zero': [0]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_bit_length(self, bit_length):
        """Covers cases of creating secrets with invalid bit lengths."""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.bit_length = bit_length

        e = self.assertRaises(Exception, self.behaviors.store_secret,
                              test_model)

        self.assertEqual(e.http_status, 400)

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
        'zero': [0],
        'oversized_string': [base.TestCase.oversized_field],
        'int': [400]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_mode(self, mode):
        """Covers cases of creating secrets with invalid modes."""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.mode = mode

        e = self.assertRaises(Exception, self.behaviors.store_secret,
                              test_model)

        self.assertEqual(e.http_status, 400)

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
    def test_secret_create_deprecated_types_and_encoding(
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
            self.assertEqual(
                base64.b64decode(test_model.payload),
                get_resp.payload
            )
        else:
            self.assertEqual(test_model.payload, str(get_resp.payload))

    @utils.parameterized_dataset({
        'large_string_content_type_and_encoding': {
            'payload_content_type': base.TestCase.oversized_field,
            'payload_content_encoding': base.TestCase.oversized_field},

        'int_content_type_and_encoding': {
            'payload_content_type': 123,
            'payload_content_encoding': 123},

        'text_content_type_none_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': ''},

        'text_no_subtype_content_type_none_content_encoding': {
            'payload_content_type': 'text',
            'payload_content_encoding': None},

        'text_slash_no_subtype_content_type_none_content_encoding': {
            'payload_content_type': 'text/',
            'payload_content_encoding': None},

        'text_content_type_empty_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': ' '},

        'text_content_type_spaces_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': ' '},

        'text_content_type_base64_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': 'base64'},

        'text_and_utf88_content_type_none_content_encoding': {
            'payload_content_type': 'text/plain; charset=utf-88',
            'payload_content_encoding': None},

        'invalid_content_type_base64_content_encoding': {
            'payload_content_type': 'invalid',
            'payload_content_encoding': 'base64'},

        'invalid_content_type_none_content_encoding': {
            'payload_content_type': 'invalid',
            'payload_content_encoding': None},

        'octet_content_type_invalid_content_encoding': {
            'payload_content_type': 'application/octet-stream',
            'payload_content_encoding': 'invalid'},

        'text_content_type_invalid_content_encoding': {
            'payload_content_type': 'text/plain',
            'payload_content_encoding': 'invalid'},

        'none_content_type_invalid_content_encoding': {
            'payload_content_type': None,
            'payload_content_encoding': 'invalid'},

        'none_content_type_base64_content_encoding': {
            'payload_content_type': None,
            'payload_content_encoding': 'base64'}
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_types_and_encoding(self, **kwargs):
        """Creating secrets with invalid payload types and encodings."""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.payload_content_encoding = kwargs[
            'payload_content_encoding']
        test_model.payload_content_type = kwargs[
            'payload_content_type']

        e = self.assertRaises(Exception, self.behaviors.store_secret,
                              test_model)

        self.assertEqual(e.http_status, 400)

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
        self.assertEqual(test_model.payload, get_resp.payload)

    @utils.parameterized_dataset({
        'list': [['boom']],
        'int': [123]
    })
    @testcase.attr('negative')
    def test_secret_create_with_invalid_payload_(self, payload):
        """Covers attempting to create secret with invalid payload types

        Tests the negative cases of invalid types (list and int).
        """
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.payload = payload

        self.assertRaises(
            exceptions.PayloadException,
            self.behaviors.store_secret,
            test_model
        )

    @utils.parameterized_dataset({
        'empty': [''],
        'none': [None],
        'zero': [0]
    })
    @testcase.attr('negative')
    def test_secret_with_no_payload_exception(self, payload):
        """Covers creating secrets with various invalid payloads.

        These requests will fail with a value error before the request to the
        server is made"""
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.payload = payload

        self.assertRaises(
            exceptions.PayloadException,
            self.behaviors.store_secret,
            test_model
        )

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
        'malformed_timezone': {
            'timezone': '-5:00',
            'days': 0}
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_expiration(self, **kwargs):
        """Create secrets with various invalid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)
        test_model = self.behaviors.create_secret(
            secret_create_defaults_data)
        test_model.expiration = timestamp

        e = self.assertRaises(Exception, self.behaviors.store_secret,
                              test_model)

        self.assertEqual(e.http_status, 400)

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
