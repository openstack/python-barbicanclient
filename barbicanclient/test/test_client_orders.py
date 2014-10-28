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
import json

import mock
from oslo.utils import timeutils
import testtools

from barbicanclient import orders, base
from barbicanclient.test import test_client
from barbicanclient.test import test_client_secrets as test_secrets


class OrdersTestCase(testtools.TestCase):
    def setUp(self):
        super(OrdersTestCase, self).setUp()
        self.secret_ref = ("http://localhost:9311/v1/secrets/"
                           "a2292306-6da0-4f60-bd8a-84fc8d692716")
        self.order_ref = ("http://localhost:9311/v1/orders/"
                          "d0460cc4-2876-4493-b7de-fc5c812883cc")
        self.key_order_data = """{{
            "status": "ACTIVE",
            "secret_ref": "{0}",
            "updated": "2014-10-21T17:15:50.871596",
            "meta": {{
                "name": "secretname",
                "algorithm": "aes",
                "payload_content_type": "application/octet-stream",
                "mode": "cbc",
                "bit_length": 256,
                "expiration": "2015-02-28T19:14:44.180394"
            }},
            "created": "2014-10-21T17:15:50.824202",
            "type": "key",
            "order_ref": "{1}"
        }}""".format(self.secret_ref, self.order_ref)
        self.api = mock.MagicMock()
        self.api._base_url = 'http://localhost:9311/v1'
        self.manager = orders.OrderManager(api=self.api)

    def _get_order_args(self, order_data):
        order_args = json.loads(order_data)
        order_args.update(order_args.pop('meta'))
        order_args.pop('type')
        return order_args


class WhenTestingKeyOrders(OrdersTestCase):

    def test_should_include_errors_in_str(self):
        order_args = self._get_order_args(self.key_order_data)
        error_code = 500
        error_reason = 'Something is broken'
        order_obj = orders.KeyOrder(api=None, error_status_code=error_code,
                                    error_reason=error_reason, **order_args)
        self.assertIn(str(error_code), str(order_obj))
        self.assertIn(error_reason, str(order_obj))

    def test_should_include_order_ref_in_repr(self):
        order_args = self._get_order_args(self.key_order_data)
        order_obj = orders.KeyOrder(api=None, **order_args)
        self.assertIn('order_ref=' + self.order_ref, repr(order_obj))

    def test_should_be_immutable_after_submit(self):
        self.api._post.return_value = {'order_ref': self.order_ref}

        order = self.manager.create_key(
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type'
        )
        order_href = order.submit()

        self.assertEqual(self.order_ref, order_href)

        # Verify that attributes are immutable after store.
        attributes = [
            "name", "expiration", "algorithm", "bit_length", "mode",
            "payload_content_type"
        ]
        for attr in attributes:
            try:
                setattr(order, attr, "test")
                self.fail("didn't raise an ImmutableException exception")
            except base.ImmutableException:
                pass

    def test_should_submit_via_constructor(self):
        self.api._post.return_value = {'order_ref': self.order_ref}

        order = self.manager.create_key(
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type'
        )
        order_href = order.submit()

        self.assertEqual(self.order_ref, order_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual('orders', entity_resp)

        # Verify that correct information was sent in the call.
        order_req = args[1]
        self.assertEqual('name', order_req['meta']['name'])
        self.assertEqual('algorithm',
                         order_req['meta']['algorithm'])
        self.assertEqual('payload_content_type',
                         order_req['meta']['payload_content_type'])

    def test_should_submit_via_attributes(self):
        self.api._post.return_value = {'order_ref': self.order_ref}

        order = self.manager.create_key()
        order.name = 'name'
        order.algorithm = 'algorithm'
        order.payload_content_type = 'payload_content_type'
        order_href = order.submit()

        self.assertEqual(self.order_ref, order_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual('orders', entity_resp)

        # Verify that correct information was sent in the call.
        order_req = args[1]
        self.assertEqual('name', order_req['meta']['name'])
        self.assertEqual('algorithm',
                         order_req['meta']['algorithm'])
        self.assertEqual('payload_content_type',
                         order_req['meta']['payload_content_type'])

    def test_should_not_be_able_to_set_generated_attributes(self):
        order = self.manager.create_key()

        # Verify that generated attributes cannot be set.
        attributes = [
            "order_ref", "secret_ref", "created", "updated", "status",
            "error_status_code", "error_reason"
        ]
        for attr in attributes:
            try:
                setattr(order, attr, "test")
                self.fail("didn't raise an AttributeError exception")
            except AttributeError:
                pass


class WhenTestingAsymmetricOrders(OrdersTestCase):

    def test_should_be_immutable_after_submit(self):
        self.api._post.return_value = {'order_ref': self.order_ref}

        order = self.manager.create_asymmetric(
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type'
        )
        order_href = order.submit()

        self.assertEqual(self.order_ref, order_href)

        # Verify that attributes are immutable after store.
        attributes = [
            "name", "expiration", "algorithm", "bit_length", "pass_phrase",
            "payload_content_type"
        ]
        for attr in attributes:
            try:
                setattr(order, attr, "test")
                self.fail(
                    "{0} didn't raise an ImmutableException exception".format(
                        attr
                    )
                )
            except base.ImmutableException:
                pass


class WhenTestingOrderManager(OrdersTestCase):

    def test_should_get(self):
        self.api._get.return_value = json.loads(self.key_order_data)

        order = self.manager.get(order_ref=self.order_ref)
        self.assertIsInstance(order, orders.KeyOrder)
        self.assertEqual(self.order_ref, order.order_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._get.call_args
        url = args[0]
        self.assertEqual(self.order_ref, url)

    def test_should_get_list(self):
        self.api._get.return_value = {
            "orders": [json.loads(self.key_order_data) for _ in range(3)]
        }

        orders_list = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(orders_list) == 3)
        self.assertIsInstance(orders_list[0], orders.KeyOrder)
        self.assertEqual(self.order_ref, orders_list[0].order_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._get.call_args
        url = args[0]
        self.assertEqual(self.api._base_url + '/orders', url)

        # Verify that correct information was sent in the call.
        params = args[1]
        self.assertEqual(10, params['limit'])
        self.assertEqual(5, params['offset'])

    def test_should_delete(self):
        self.manager.delete(order_ref=self.order_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._delete.call_args
        url = args[0]
        self.assertEqual(self.order_ref, url)

    def test_should_fail_delete_no_href(self):
        self.assertRaises(ValueError, self.manager.delete, None)

    def test_should_get_total(self):
        self.api._get.return_value = {'total': 1}
        total = self.manager.total()
        self.assertEqual(total, 1)
