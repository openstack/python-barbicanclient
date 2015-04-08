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
import pytz
import sys

from testtools import testcase
from functionaltests import utils
from functionaltests.client import base
from functionaltests.client.v1.behaviors import order_behaviors
from functionaltests.client.v1.behaviors import secret_behaviors
from oslo_utils import timeutils

from barbicanclient import exceptions

order_create_key_data = {
    "name": "barbican functional test secret name",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload_content_type": "application/octet-stream",
}

# Any field with None will be created in the model with None as the value
# but will be omitted in the final request (via the requests package)
# to the server.
#
# Given that fact, order_create_nones_data is effectively an empty json request
# to the server.
order_create_nones_data = {
    "name": None,
    "algorithm": None,
    "bit_length": None,
    "mode": None,
    "payload_content_type": None,
}


@utils.parameterized_test_case
class OrdersTestCase(base.TestCase):

    def setUp(self):
        super(OrdersTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(
            self.barbicanclient)
        self.secret_behaviors = secret_behaviors.SecretBehaviors(
            self.barbicanclient)

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(OrdersTestCase, self).tearDown()

    @testcase.skip('Launchpad 1425667')
    @testcase.attr('positive')
    def test_create_order_defaults_wout_name(self):
        """Create an order without the name attribute."""

        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.name = None
        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        get_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(get_resp.name, test_model.name)

    @testcase.skip('Launchpad 1420444')
    @testcase.attr('positive')
    def test_create_order_defaults_w_empty_name(self):
        """Create an order the name attribute an empty string."""

        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.name = ""
        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        get_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(get_resp.name, test_model.name)

    @testcase.skip('Launchpad 1425667')
    @testcase.attr('positive')
    def test_create_order_defaults_payload_content_type_none(self):
        """Covers creating orders with various valid payload content types."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.payload_content_type = None

        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

    @testcase.attr('positive')
    def test_create_order_defaults_check_empty_name(self):
        """Create order with empty meta name.

        The resulting secret name should be a UUID.
        """

        # first create an order with defaults
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.name = ""

        order_ref = self.behaviors.store_order(test_model)

        # verify that the order was created successfully
        self.assertIsNotNone(order_ref)

        # given the order href, retrieve the order
        order_resp = self.behaviors.get_order(order_ref)

        # verify that the get was successful
        self.assertTrue(order_resp.status == "ACTIVE" or
                        order_resp.status == "PENDING")

        # verify the new secret's name matches the name in the secret ref
        # in the newly created order.
        secret_resp = self.secret_behaviors.get_secret(
            order_resp.secret_ref)
        self.assertEqual(secret_resp.name, test_model.name)

    @testcase.attr('positive')
    def test_order_and_secret_metadata_same(self):
        """Checks that metadata from secret GET and order GET are the same.

        Covers checking that secret metadata from a get on the order and
        secret metadata from a get on the secret are the same. Assumes
        that the order status will be active and not pending.
        """
        test_model = self.behaviors.create_key_order(order_create_key_data)

        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        order_resp = self.behaviors.get_order(order_ref)
        self.assertIsNotNone(order_resp.secret_ref)
        secret_ref = order_resp.secret_ref

        secret_resp = self.secret_behaviors.get_secret(secret_ref)

        self.assertEqual(order_resp.name,
                         secret_resp.name,
                         'Names were not the same')
        self.assertEqual(order_resp.algorithm,
                         secret_resp.algorithm,
                         'Algorithms were not the same')
        self.assertEqual(order_resp.bit_length,
                         secret_resp.bit_length,
                         'Bit lengths were not the same')
        self.assertEqual(order_resp.expiration,
                         secret_resp.expiration,
                         'Expirations were not the same')
        self.assertEqual(order_resp.mode,
                         secret_resp.mode,
                         'Modes were not the same')

    @testcase.attr('negative')
    def test_get_order_defaults_that_doesnt_exist(self):
        """Covers case of getting a non-existent order."""
        ref = self.behaviors.base_url + '/orders/notauuid'
        # try to get a non-existent order
        e = self.assertRaises(ValueError, self.behaviors.get_order, ref)

        # verify that the order get failed
        self.assertEqual(e.message, 'Order incorrectly specified.')

    @testcase.attr('negative')
    def test_get_order_defaults_that_doesnt_exist_valid_uuid(self):
        """Covers case of getting a non-existent order with a valid UUID"""
        uuid = '54262d9d-4bc7-4821-8df0-dc2ca8e112bb'
        ref = self.behaviors.base_url + '/orders/' + uuid

        # try to get a non-existent order
        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.get_order,
            ref
        )

        # verify that the order get failed
        self.assertEqual(e.status_code, 404)

    @testcase.attr('negative')
    def test_create_order_nones(self):
        """Covers order creation with empty JSON."""

        test_model = self.behaviors.create_key_order(order_create_nones_data)

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )

        self.assertEqual(e.status_code, 400)

    @testcase.attr('negative')
    def test_create_order_empty_entries(self):
        """Covers order creation with empty JSON."""

        test_model = self.behaviors.create_key_order(order_create_nones_data)
        test_model.name = ""
        test_model.algorithm = ""
        test_model.mode = ""
        test_model.bit_length = ""
        test_model.payload_content_type = ""

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )

        self.assertEqual(e.status_code, 400)

    @testcase.attr('negative')
    def test_create_order_defaults_oversized_strings(self):
        """Covers order creation with empty JSON."""

        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.name = base.TestCase.oversized_field
        test_model.algorithm = base.TestCase.oversized_field
        test_model.mode = base.TestCase.oversized_field

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )

        self.assertEqual(e.status_code, 400)

    @utils.parameterized_dataset({
        '8': [8],
        '64': [64],
        '128': [128],
        '192': [192],
        '256': [256],
        '1024': [1024],
        '2048': [2048],
        '4096': [4096]
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_bit_length(self, bit_length):
        """Covers creating orders with various valid bit lengths."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.bit_length = bit_length

        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        get_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(get_resp.bit_length, test_model.bit_length)

    @utils.parameterized_dataset({
        'negative_maxint': [-sys.maxint],
        'negative_7': [-7],
        'negative_1': [-1],
        '0': [0],
        '1': [1],
        '7': [7],
        '129': [129],
        'none': [None],
        'empty': [''],
        'space': [' '],
        'over_signed_small_int': [32768]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_bit_length(self, bit_length):
        """Covers creating orders with various invalid bit lengths."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.bit_length = bit_length

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )
        self.assertEqual(e.status_code, 400)

    @utils.parameterized_dataset({
        'alphanumeric': ['1f34ds'],
        'len_255': [base.TestCase.max_sized_field],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?']
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_name(self, name):
        """Covers creating orders with various valid names."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.name = name

        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        get_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(get_resp.name, test_model.name)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_name(self, name):
        """Covers creating orders with various invalid names."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.name = name

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )

        self.assertEqual(e.status_code, 400)

    @utils.parameterized_dataset({
        'cbc': ['cbc']
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_mode(self, mode):
        """Covers creating orders with various valid modes."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.mode = mode

        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        get_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(get_resp.mode, test_model.mode)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_mode(self, mode):
        """Covers creating orders with various invalid modes."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.mode = mode

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )
        self.assertEqual(e.status_code, 400)

    @utils.parameterized_dataset({
        'aes': ['aes']
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_algorithm(self, algorithm):
        """Covers creating orders with various valid algorithms."""
        test_model = self.behaviors.create_key_order(
            order_create_key_data)
        test_model.algorithm = algorithm

        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        get_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(get_resp.algorithm, test_model.algorithm)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_algorithm(self, algorithm):
        """Covers creating orders with various invalid algorithms."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.algorithm = algorithm

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )

        self.assertEqual(e.status_code, 400)

    # TODO(tdink) Add empty after Launchpad 1420444 is resolved
    @utils.parameterized_dataset({
        'text/plain': ['text/plain'],
        'text_plain_space_charset_utf8': ['text/plain; charset=utf-8'],
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_payload_content_type(self, pct):
        """Covers order creation with various valid payload content types."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.payload_content_type = pct

        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        get_resp = self.behaviors.get_order(order_ref)
        self.assertEqual(get_resp.payload_content_type,
                         test_model.payload_content_type)

    @utils.parameterized_dataset({
        'int': [123],
        'invalid': ['invalid'],
        'oversized_string': [base.TestCase.oversized_field],
        'text': ['text'],
        'text_slash_with_no_subtype': ['text/'],
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_payload_content_type(self, pct):
        """Covers order creation with various invalid payload content types."""
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.payload_content_type = pct

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )

        self.assertEqual(e.status_code, 400)

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
    def test_create_order_defaults_valid_expiration(self, **kwargs):
        """Covers creating orders with various valid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)

        date = timeutils.parse_isotime(timestamp)
        date = date.astimezone(pytz.utc)

        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.expiration = timestamp

        order_ref = self.behaviors.store_order(test_model)
        self.assertIsNotNone(order_ref)

        get_resp = self.behaviors.get_order(order_ref)
        self.assertIsNotNone(get_resp)
        self.assertEqual(date, get_resp.expiration)

    @utils.parameterized_dataset({
        'malformed_timezone': {
            'timezone': '-5:00',
            'days': 5},
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_expiration(self, **kwargs):
        """Covers creating orders with various invalid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)
        test_model = self.behaviors.create_key_order(order_create_key_data)
        test_model.expiration = timestamp

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.behaviors.store_order,
            test_model
        )

        self.assertEqual(e.status_code, 400)
