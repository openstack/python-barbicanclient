"""
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from functionaltests.client.v1.behaviors import base_behaviors


class OrderBehaviors(base_behaviors.BaseBehaviors):

    def create_key_order(self, data):
        """Create a key order from the data in the model.

        :param data: The data used to create the order
        :return: The create response and href for the order
        """

        return self.client.orders.create_key(**data)

    def create_asymmetric_order(self, data):
        """Create an asymmetric order from the data in the model.

        :param data: The data used to create the order
        :return: The create response and href for the order
        """

        return self.client.orders.create_asymmetric(**data)

    def store_order(self, order):
        """Stores an order object in the barbican database

        :return: The order href
        """

        resp = order.submit()
        order_ref = str(resp)

        if order_ref:
            self.created_entities.append(order_ref)

        return resp

    def get_order(self, order_ref):
        """Get an order from an href.

        :param order_ref: The href for an order
        :return: The response from the get
        """
        return self.client.orders.get(order_ref)

    def get_orders(self, limit=10, offset=0):
        """Get a list of orders.

        :param limit: limits number of returned orders (default 10)
        :param offset: represents how many records to skip before retrieving
                       the list (default 0)
        :return the response, a list of orders and the next/pref hrefs
        """

        orders = self.client.orders.list(limit, offset)

        return orders

    def delete_order(self, order_ref, expected_fail=False):
        """Delete an order.

        :param order_ref: HATEOS ref of the order to be deleted
        :param expected_fail: Flag telling the delete whether or not this
                              operation is expected to fail (ie coming
                              from a negative test).  We need this to
                              determine whether or not this delete should
                              also remove an entity from our internal
                              list for housekeeping.
        :return A request response object
        """
        resp = self.client.orders.delete(order_ref)
        if not expected_fail:
            self.created_entities.remove(order_ref)
        return resp

    def delete_all_created_orders(self):
        """Delete all of the orders that we have created."""
        orders_to_delete = [order for order in self.created_entities]
        for order_ref in orders_to_delete:
            self.delete_order(order_ref)
