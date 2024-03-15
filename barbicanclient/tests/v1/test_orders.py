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

from oslo_serialization import jsonutils
from oslo_utils import timeutils
import uuid

from barbicanclient import base
from barbicanclient.tests import test_client
from barbicanclient.v1 import orders


class OrdersTestCase(test_client.BaseEntityResource):
    def setUp(self):
        self._setUp('orders', entity_id='d0460cc4-2876-4493-b7de-fc5c812883cc')

        self.secret_ref = (self.endpoint +
                           '/secrets/a2292306-6da0-4f60-bd8a-84fc8d692716')

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
        }}""".format(self.secret_ref, self.entity_href)

        self.key_order_invalid_data = """{{
            "status": "ACTIVE",
            "secret_ref": "{0}",
            "updated": "2014-10-21T17:15:50.871596",
            "meta": {{
                "name": "secretname",
                "algorithm": "aes",
                "request_type":"invalid",
                "payload_content_type": "application/octet-stream",
                "mode": "cbc",
                "bit_length": 256,
                "expiration": "2015-02-28T19:14:44.180394"
            }},
            "created": "2014-10-21T17:15:50.824202",
            "type": "key",
            "order_ref": "{1}"
        }}""".format(self.secret_ref, self.entity_href)

        self.container_ref = (
            self.endpoint + '/containers/a2292306-6da0-4f60-bd8a-84fc8d692716')
        self.source_container_ref = (
            self.endpoint + '/containers/c6f20480-c1e5-442b-94a0-cb3b5e0cf179')

        self.cert_order_data = """{{
            "status": "ACTIVE",
            "container_ref": "{0}",
            "updated": "2014-10-21T17:15:50.871596",
            "meta": {{
                "name": "secretname",
                "subject_dn": "cn=server.example.com,o=example.com",
                "request_type": "stored-key",
                "container_ref": "{1}"
            }},
            "created": "2014-10-21T17:15:50.824202",
            "type": "certificate",
            "order_ref": "{2}"
        }}""".format(self.container_ref, self.source_container_ref,
                     self.entity_href)

        self.manager = self.client.orders

    def _get_order_args(self, order_data):
        order_args = jsonutils.loads(order_data)
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
        self.assertIn('order_ref=' + self.entity_href, repr(order_obj))

    def test_should_be_immutable_after_submit(self):
        data = {'order_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        order = self.manager.create_key(
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type'
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

    def test_should_submit_via_constructor(self):
        data = {'order_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        order = self.manager.create_key(
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type'
        )
        order_href = order.submit()

        self.assertEqual(self.entity_href, order_href)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base + '/',
                         self.responses.last_request.url)

        # Verify that correct information was sent in the call.
        order_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual('name', order_req['meta']['name'])
        self.assertEqual('algorithm',
                         order_req['meta']['algorithm'])
        self.assertEqual('payload_content_type',
                         order_req['meta']['payload_content_type'])

    def test_should_submit_via_attributes(self):
        data = {'order_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        order = self.manager.create_key()
        order.name = 'name'
        order.algorithm = 'algorithm'
        order.payload_content_type = 'payload_content_type'
        order_href = order.submit()

        self.assertEqual(self.entity_href, order_href)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base + '/',
                         self.responses.last_request.url)

        # Verify that correct information was sent in the call.
        order_req = jsonutils.loads(self.responses.last_request.text)
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

    def test_should_delete_from_object(self, order_ref=None):
        order_ref = order_ref or self.entity_href

        data = {'order_ref': order_ref}
        self.responses.post(self.entity_base + '/', json=data)
        self.responses.delete(self.entity_href, status_code=204)

        order = self.manager.create_key(
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type'
        )
        order_href = order.submit()

        self.assertEqual(order_ref, order_href)

        order.delete()

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

    def test_should_delete_from_object_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_delete_from_object(bad_href)

    def test_should_delete_from_object_using_only_uuid(self):
        self.test_should_delete_from_object(self.entity_id)


class WhenTestingAsymmetricOrders(OrdersTestCase):

    def test_should_be_immutable_after_submit(self):
        data = {'order_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        order = self.manager.create_asymmetric(
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type'
        )
        order_href = order.submit()

        self.assertEqual(self.entity_href, order_href)

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

    def test_create_asymmetric_order_w_passphrase(self):
        data = {'order_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        passphrase = str(uuid.uuid4())
        order = orders.AsymmetricOrder(
            api=self.manager._api,
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type',
            passphrase=passphrase,
        )
        order_href = order.submit()
        self.assertEqual(self.entity_href, order_href)
        self.assertEqual(passphrase, order.pass_phrase)

    def test_create_asymmetric_order_w_legacy_pass_phrase_param(self):
        data = {'order_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        passphrase = str(uuid.uuid4())
        order = orders.AsymmetricOrder(
            api=self.manager._api,
            name='name',
            algorithm='algorithm',
            payload_content_type='payload_content_type',
            pass_phrase=passphrase,
        )
        order_href = order.submit()
        self.assertEqual(self.entity_href, order_href)
        self.assertEqual(passphrase, order.pass_phrase)


class WhenTestingOrderManager(OrdersTestCase):

    def test_should_get(self, order_ref=None):
        order_ref = order_ref or self.entity_href

        self.responses.get(self.entity_href, text=self.key_order_data)

        order = self.manager.get(order_ref=order_ref)
        self.assertIsInstance(order, orders.KeyOrder)
        self.assertEqual(self.entity_href, order.order_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

    def test_should_get_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_get(bad_href)

    def test_should_get_using_only_uuid(self):
        self.test_should_get(self.entity_id)

    def test_should_get_invalid_meta(self):
        self.responses.get(self.entity_href, text=self.key_order_invalid_data)

        # Verify checking for invalid meta fields.
        self.assertRaises(TypeError,
                          self.manager.get,
                          self.entity_href)

    def test_should_get_list(self):
        data = {"orders": [jsonutils.loads(self.key_order_data)
                           for _ in range(3)]}
        self.responses.get(self.entity_base, json=data)

        orders_list = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(orders_list) == 3)
        self.assertIsInstance(orders_list[0], orders.KeyOrder)
        self.assertEqual(self.entity_href, orders_list[0].order_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base,
                         self.responses.last_request.url.split('?')[0])

        # Verify that correct information was sent in the call.
        self.assertEqual(['10'], self.responses.last_request.qs['limit'])
        self.assertEqual(['5'], self.responses.last_request.qs['offset'])

    def test_should_delete(self, order_ref=None):
        order_ref = order_ref or self.entity_href
        self.responses.delete(self.entity_href, status_code=204)

        self.manager.delete(order_ref=order_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

    def test_should_delete_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_delete(bad_href)

    def test_should_delete_using_only_uuid(self):
        self.test_should_delete(self.entity_id)

    def test_should_fail_delete_no_href(self):
        self.assertRaises(ValueError, self.manager.delete, None)

    def test_should_get_total(self):
        self.responses.get(self.entity_base, json={'total': 1})
        total = self.manager.total()
        self.assertEqual(1, total)

    def test_get_formatted_data(self):
        self.responses.get(self.entity_href, text=self.key_order_data)

        order = self.manager.get(order_ref=self.entity_href)
        data = order._get_formatted_data()

        order_args = self._get_order_args(self.key_order_data)
        self.assertEqual(timeutils.parse_isotime(
                         order_args['created']).isoformat(),
                         data[4])
