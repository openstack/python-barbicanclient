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

from barbicanclient import orders
from barbicanclient.openstack.common import timeutils
from barbicanclient.test import test_client
from barbicanclient.test import test_client_secrets as test_secrets


class OrderData(object):
    def __init__(self):
        self.created = str(timeutils.utcnow())

        self.secret = test_secrets.SecretData()
        self.order_dict = {'created': self.created,
                           'secret': self.secret.get_dict()}

    def get_dict(self, order_ref, secret_ref=None):
        order = self.order_dict
        order['order_ref'] = order_ref
        if secret_ref:
            order['secret_ref'] = secret_ref
        return order


class WhenTestingOrdersManager(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('orders')

        self.order = OrderData()

        self.manager = orders.OrderManager(self.api)

    def test_should_create(self):
        self.api.post.return_value = {'order_ref': self.entity_href}

        order_href = self.manager\
            .create(name=self.order.secret.name,
                    algorithm=self.order.secret.algorithm,
                    payload_content_type=self.order.secret.content)

        self.assertEqual(self.entity_href, order_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        order_req = args[1]
        self.assertEqual(self.order.secret.name, order_req['secret']['name'])
        self.assertEqual(self.order.secret.algorithm,
                         order_req['secret']['algorithm'])
        self.assertEqual(self.order.secret.payload_content_type,
                         order_req['secret']['payload_content_type'])

    def test_should_get(self):
        self.api.get.return_value = self.order.get_dict(self.entity_href)

        order = self.manager.get(order_ref=self.entity_href)
        self.assertIsInstance(order, orders.Order)
        self.assertEqual(self.entity_href, order.order_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_delete(self):
        self.manager.delete(order_ref=self.entity_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.delete.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_fail_get_no_href(self):
        with self.assertRaises(ValueError):
            self.manager.get(None)

    def test_should_fail_delete_no_href(self):
        with self.assertRaises(ValueError):
            self.manager.delete(None)
