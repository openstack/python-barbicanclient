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

from oslo.utils import timeutils

from barbicanclient import orders, base
from barbicanclient.test import test_client
from barbicanclient.test import test_client_secrets as test_secrets


class OrderData(object):
    def __init__(self):
        self.created = str(timeutils.utcnow())

        self.secret = test_secrets.SecretData()
        self.status = 'ACTIVE'
        self.order_dict = {'created': self.created,
                           'status': self.status,
                           'secret': self.secret.get_dict()}

    def get_dict(self, order_ref, secret_ref=None):
        order = self.order_dict
        order['order_ref'] = order_ref
        if secret_ref:
            order['secret_ref'] = secret_ref
        return order


class WhenTestingOrders(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('orders')

        self.order = OrderData()

        self.manager = orders.OrderManager(self.api)

    def test_should_entity_str(self):
        order = self.order.get_dict(self.entity_href)
        error_code = 500
        error_reason = 'Something is broken'
        order_obj = orders.Order(api=None, error_status_code=error_code,
                                 error_reason=error_reason, **order)
        self.assertIn(self.order.status, str(order_obj))
        self.assertIn(str(error_code), str(order_obj))
        self.assertIn(error_reason, str(order_obj))

    def test_should_entity_repr(self):
        order = self.order.get_dict(self.entity_href)
        order_obj = orders.Order(api=None, **order)
        self.assertIn('order_ref=' + self.entity_href, repr(order_obj))

    def test_should_submit_via_constructor(self):
        self.api._post.return_value = {'order_ref': self.entity_href}

        order = self.manager.create(
            name=self.order.secret.name,
            algorithm=self.order.secret.algorithm,
            payload_content_type=self.order.secret.content
        )
        order_href = order.submit()

        self.assertEqual(self.entity_href, order_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        order_req = args[1]
        self.assertEqual(self.order.secret.name, order_req['secret']['name'])
        self.assertEqual(self.order.secret.algorithm,
                         order_req['secret']['algorithm'])
        self.assertEqual(self.order.secret.payload_content_type,
                         order_req['secret']['payload_content_type'])

    def test_should_submit_via_attributes(self):
        self.api._post.return_value = {'order_ref': self.entity_href}

        order = self.manager.create()
        order.name = self.order.secret.name
        order.algorithm = self.order.secret.algorithm
        order.payload_content_type = self.order.secret.content
        order_href = order.submit()

        self.assertEqual(self.entity_href, order_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        order_req = args[1]
        self.assertEqual(self.order.secret.name, order_req['secret']['name'])
        self.assertEqual(self.order.secret.algorithm,
                         order_req['secret']['algorithm'])
        self.assertEqual(self.order.secret.payload_content_type,
                         order_req['secret']['payload_content_type'])

    def test_should_be_immutable_after_submit(self):
        self.api._post.return_value = {'order_ref': self.entity_href}

        order = self.manager.create(
            name=self.order.secret.name,
            algorithm=self.order.secret.algorithm,
            payload_content_type=self.order.secret.content
        )
        order_href = order.submit()

        self.assertEqual(self.entity_href, order_href)

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

    def test_should_not_be_able_to_set_generated_attributes(self):
        order = self.manager.create()

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

    def test_should_get(self):
        self.api._get.return_value = self.order.get_dict(self.entity_href)

        order = self.manager.get(order_ref=self.entity_href)
        self.assertIsInstance(order, orders.Order)
        self.assertEqual(self.entity_href, order.order_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_delete(self):
        self.manager.delete(order_ref=self.entity_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._delete.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_get_list(self):
        order_resp = self.order.get_dict(self.entity_href)
        self.api._get.return_value = {"orders":
                                      [order_resp for v in range(3)]}

        orders_list = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(orders_list) == 3)
        self.assertIsInstance(orders_list[0], orders.Order)
        self.assertEqual(self.entity_href, orders_list[0].order_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._get.call_args
        url = args[0]
        self.assertEqual(self.entity_base[:-1], url)

        # Verify that correct information was sent in the call.
        params = args[1]
        self.assertEqual(10, params['limit'])
        self.assertEqual(5, params['offset'])

    def test_should_fail_delete_no_href(self):
        self.assertRaises(ValueError, self.manager.delete, None)

    def test_should_get_total(self):
        self.api._get.return_value = {'total': 1}
        total = self.manager.total()
        self.assertEqual(total, 1)
