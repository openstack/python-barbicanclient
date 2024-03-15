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
import datetime
import sys

from functionaltests.client import base
from functionaltests.common import cleanup
from functionaltests import utils
from oslo_utils import timeutils
from testtools import testcase

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
        self.cleanup = cleanup.CleanUp(self.barbicanclient)

    def tearDown(self):
        self.cleanup.delete_all_entities()
        super(OrdersTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_create_order_defaults_wout_name(self):
        """Create an order without the name attribute."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.name = None
        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertEqual(order.name, order_resp.name)

    @testcase.attr('positive')
    def test_create_order_defaults_w_empty_name(self):
        """Create an order the name attribute an empty string."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.name = ""
        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertEqual(order.name, order_resp.name)

    @testcase.skip('Launchpad 1425667')
    @testcase.attr('positive')
    def test_create_order_defaults_payload_content_type_none(self):
        """Covers creating orders with various valid payload content types."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.payload_content_type = None

        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertTrue(order_resp.status == "ACTIVE" or
                        order_resp.status == "PENDING")

    @testcase.attr('positive')
    def test_create_order_defaults_check_empty_name(self):
        """Create order with empty meta name.

        The resulting secret name should be a UUID.
        """

        # first create an order with defaults
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.name = ""

        order_ref = self.cleanup.add_entity(order)

        # verify that the order was created successfully
        self.assertIsNotNone(order_ref)

        # given the order href, retrieve the order
        order_resp = self.barbicanclient.orders.get(order_ref)

        # verify that the get was successful
        self.assertTrue(order_resp.status == "ACTIVE" or
                        order_resp.status == "PENDING")

        # verify the new secret's name matches the name in the secret ref
        # in the newly created order.
        secret_resp = self.barbicanclient.secrets.get(order_resp.secret_ref)
        self.assertEqual(order.name, secret_resp.name)

    @testcase.attr('positive')
    def test_order_and_secret_metadata_same(self):
        """Checks that metadata from secret GET and order GET are the same.

        Covers checking that secret metadata from a get on the order and
        secret metadata from a get on the secret are the same. Assumes
        that the order status will be active and not pending.
        """
        order = self.barbicanclient.orders.create_key(**order_create_key_data)

        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertIsNotNone(order_resp.secret_ref)

        secret_resp = self.barbicanclient.secrets.get(order_resp.secret_ref)

        self.assertEqual(secret_resp.name,
                         order_resp.name,
                         'Names were not the same')
        self.assertEqual(secret_resp.algorithm,
                         order_resp.algorithm,
                         'Algorithms were not the same')
        self.assertEqual(secret_resp.bit_length,
                         order_resp.bit_length,
                         'Bit lengths were not the same')
        self.assertEqual(secret_resp.expiration,
                         order_resp.expiration,
                         'Expirations were not the same')
        self.assertEqual(secret_resp.mode,
                         order_resp.mode,
                         'Modes were not the same')

    @testcase.attr('negative')
    def test_get_order_defaults_that_doesnt_exist(self):
        """Covers case of getting a non-existent order."""
        ref = self.barbicanclient.orders._api.endpoint_override + \
            '/orders/notauuid'
        # try to get a non-existent order
        e = self.assertRaises(ValueError, self.barbicanclient.orders.get, ref)

        # verify that the order get failed
        self.assertEqual('Order incorrectly specified.', str(e))

    @testcase.attr('negative')
    def test_get_order_defaults_that_doesnt_exist_valid_uuid(self):
        """Covers case of getting a non-existent order with a valid UUID"""
        uuid = '54262d9d-4bc7-4821-8df0-dc2ca8e112bb'
        ref = self.barbicanclient.orders._api.endpoint_override + \
            '/orders/' + uuid

        # try to get a non-existent order
        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.barbicanclient.orders.get,
            ref
        )

        # verify that the order get failed
        self.assertEqual(404, e.status_code)

    @testcase.attr('negative')
    def test_create_order_nones(self):
        """Covers order creation with empty JSON."""
        order = self.barbicanclient.orders.create_key(
            **order_create_nones_data)

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )

        self.assertEqual(400, e.status_code)

    @testcase.attr('negative')
    def test_create_order_empty_entries(self):
        """Covers order creation with empty JSON."""
        order = self.barbicanclient.orders.create_key(
            **order_create_nones_data)
        order.name = ""
        order.algorithm = ""
        order.mode = ""
        order.bit_length = ""
        order.payload_content_type = ""

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )

        self.assertEqual(400, e.status_code)

    @testcase.attr('negative')
    def test_create_order_defaults_oversized_strings(self):
        """Covers order creation with empty JSON."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.name = base.TestCase.oversized_field
        order.algorithm = base.TestCase.oversized_field
        order.mode = base.TestCase.oversized_field

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )

        self.assertEqual(400, e.status_code)

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
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.bit_length = bit_length

        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertEqual(order.bit_length, order_resp.bit_length)

    @utils.parameterized_dataset({
        'negative_maxsize': [-sys.maxsize],
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
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.bit_length = bit_length

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )
        self.assertEqual(400, e.status_code)

    @utils.parameterized_dataset({
        'alphanumeric': ['1f34ds'],
        'len_255': [base.TestCase.max_sized_field],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?']
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_name(self, name):
        """Covers creating orders with various valid names."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.name = name

        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertEqual(order.name, order_resp.name)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_name(self, name):
        """Covers creating orders with various invalid names."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.name = name

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )

        self.assertEqual(400, e.status_code)

    @utils.parameterized_dataset({
        'cbc': ['cbc']
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_mode(self, mode):
        """Covers creating orders with various valid modes."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.mode = mode

        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertEqual(order.mode, order_resp.mode)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_mode(self, mode):
        """Covers creating orders with various invalid modes."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.mode = mode

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )
        self.assertEqual(400, e.status_code)

    @utils.parameterized_dataset({
        'aes': ['aes']
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_algorithm(self, algorithm):
        """Covers creating orders with various valid algorithms."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.algorithm = algorithm

        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertEqual(order.algorithm, order_resp.algorithm)

    @utils.parameterized_dataset({
        'int': [123]
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_algorithm(self, algorithm):
        """Covers creating orders with various invalid algorithms."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.algorithm = algorithm

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )

        self.assertEqual(400, e.status_code)

    # TODO(tdink) Add empty after Launchpad 1420444 is resolved
    @utils.parameterized_dataset({
        'text/plain': ['text/plain'],
        'text_plain_space_charset_utf8': ['text/plain; charset=utf-8'],
    })
    @testcase.attr('positive')
    def test_create_order_defaults_valid_payload_content_type(self, pct):
        """Covers order creation with various valid payload content types."""
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.payload_content_type = pct

        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertEqual(order.payload_content_type,
                         order_resp.payload_content_type)

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
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.payload_content_type = pct

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )

        self.assertEqual(400, e.status_code)

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
        date = date.astimezone(datetime.timezone.utc)

        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.expiration = timestamp

        order_ref = self.cleanup.add_entity(order)
        self.assertIsNotNone(order_ref)

        order_resp = self.barbicanclient.orders.get(order_ref)
        self.assertIsNotNone(order_resp)
        self.assertEqual(date, order_resp.expiration)

    @utils.parameterized_dataset({
        'malformed_timezone': {
            'timezone': '-5:00',
            'days': 5},
    })
    @testcase.attr('negative')
    def test_create_order_defaults_invalid_expiration(self, **kwargs):
        """Covers creating orders with various invalid expiration data."""
        timestamp = utils.create_timestamp_w_tz_and_offset(**kwargs)
        order = self.barbicanclient.orders.create_key(**order_create_key_data)
        order.expiration = timestamp

        e = self.assertRaises(
            exceptions.HTTPClientError,
            order.submit
        )

        self.assertEqual(400, e.status_code)
