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
import logging

from barbicanclient import base
from barbicanclient.openstack.common.gettextutils import _
from barbicanclient.openstack.common import timeutils


LOG = logging.getLogger(__name__)


class Order(object):

    def __init__(self, order_dict):
        """
        Builds an order object from a dictionary.
        """
        self.order_ref = order_dict['order_ref']

        self.error_status_code = order_dict.get('error_status_code', None)
        self.error_reason = order_dict.get('error_reason', None)
        self.status = order_dict.get('status')
        self.created = timeutils.parse_isotime(order_dict['created'])
        if order_dict.get('updated') is not None:
            self.updated = timeutils.parse_isotime(order_dict['updated'])
        else:
            self.updated = None
        self.secret_ref = order_dict.get('secret_ref')

    def __str__(self):
        strg = ("Order - order href: {0}\n"
                "        secret href: {1}\n"
                "        created: {2}\n"
                "        status: {3}\n"
                ).format(self.order_ref, self.secret_ref,
                         self.created, self.status)

        if self.error_status_code:
            strg = ''.join([strg, ("        error_status_code: {0}\n"
                                   "        error_reason: {1}\n"
                                   ).format(self.error_status_code,
                                            self.error_reason)])
        return strg

    def __repr__(self):
        return 'Order(order_ref={0})'.format(self.order_ref)


class OrderManager(base.BaseEntityManager):

    def __init__(self, api):
        super(OrderManager, self).__init__(api, 'orders')

    def create(self,
               name=None,
               payload_content_type='application/octet-stream',
               algorithm=None,
               bit_length=None,
               mode=None,
               expiration=None):
        """
        Creates a new Order in Barbican

        :param name: A friendly name for the secret
        :param payload_content_type: The format/type of the secret data
        :param algorithm: The algorithm the secret associated with
        :param bit_length: The bit length of the secret
        :param mode: The algorithm mode (e.g. CBC or CTR mode)
        :param expiration: The expiration time of the secret in ISO 8601
            format
        :returns: Order href for the created order
        """
        LOG.debug(_("Creating order"))

        order_dict = {'secret': {}}
        order_dict['secret']['name'] = name
        order_dict['secret'][
            'payload_content_type'] = payload_content_type
        order_dict['secret']['algorithm'] = algorithm
        order_dict['secret']['bit_length'] = bit_length
        order_dict['secret']['mode'] = mode
        order_dict['secret']['expiration'] = expiration
        self._remove_empty_keys(order_dict['secret'])

        LOG.debug(_("Request body: {0}").format(order_dict['secret']))

        resp = self.api.post(self.entity, order_dict)
        return resp['order_ref']

    def get(self, order_ref):
        """
        Returns an Order object

        :param order_ref: The href for the order
        """
        LOG.debug(_("Getting order - Order href: {0}").format(order_ref))
        if not order_ref:
            raise ValueError('order_ref is required.')
        resp = self.api.get(order_ref)
        return Order(resp)

    def delete(self, order_ref):
        """
        Deletes an order

        :param order_ref: The href for the order
        """
        if not order_ref:
            raise ValueError('order_ref is required.')
        self.api.delete(order_ref)

    def list(self, limit=10, offset=0):
        """
        Lists all orders for the tenant

        :param limit: Max number of orders returned
        :param offset: Offset orders to begin list
        :returns: list of Order objects
        """
        LOG.debug('Listing orders - offset {0} limit {1}'.format(offset,
                                                                 limit))
        href = '{0}/{1}'.format(self.api.base_url, self.entity)
        params = {'limit': limit, 'offset': offset}
        resp = self.api.get(href, params)

        return [Order(o) for o in resp['orders']]
