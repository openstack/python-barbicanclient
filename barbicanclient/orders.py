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
from urlparse import urlparse

from openstack.common.gettextutils import _
from openstack.common import log as logging
from openstack.common.timeutils import parse_isotime

from barbicanclient import base
from barbicanclient import secrets


LOG = logging.getLogger(__name__)


class Order(object):

    def __init__(self, order_dict):
        """
        Builds an order object from a json representation. Includes the
        connection object for subtasks.
        """
        self.order_ref = order_dict['order_ref']
        self.status = order_dict.get('status')
        self.created = parse_isotime(order_dict['created'])
        if order_dict.get('updated') is not None:
            self.updated = parse_isotime(order_dict['updated'])
        else:
            self.updated = None
        secret_dict = order_dict['secret']
        #TODO(dmend): This is a hack because secret_ref is in different
        #             spots.  Secret will be missing content_types also.
        #             Maybe we should fetch the secret for this?
        secret_dict.update({'secret_ref': order_dict['secret_ref'],
                            'created': order_dict['created']})
        self.secret = secrets.Secret(secret_dict)

        self.id = urlparse(self.order_ref).path.split('/').pop()

    def __str__(self):
        return ("Order - ID: {0}\n"
                "        order href: {1}\n"
                "        secret href: {2}\n"
                "        created: {3}\n"
                "        status: {4}\n"
                .format(self.id, self.order_ref, self.secret.secret_ref,
                        self.created, self.status)
                )

    def __repr__(self):
        return 'Order(id="{0}", secret=Secret(id="{1}")'.format(
            self.id, self.secret.id
        )


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

        :param name: A friendly name for the
        :param payload_content_type: The format/type of the secret data
        :param algorithm: The algorithm the secret is used with
        :param bit_length: The bit length of the secret
        :param mode: The algorithm mode (e.g. CBC or CTR mode)
        :param expiration: The expiration time of the secret in ISO 8601
            format
        :returns: Order ID for the created order
        """
        LOG.debug(_("Creating order"))

        order_dict = {'secret': {}}
        order_dict['secret']['name'] = name
        order_dict['secret'][
            'payload_content_type'] = payload_content_type
        order_dict['secret']['algorithm'] = algorithm
        order_dict['secret']['bit_length'] = bit_length
        #TODO(dmend): Change this to mode
        order_dict['secret']['cypher_type'] = mode
        order_dict['secret']['expiration'] = expiration
        self._remove_empty_keys(order_dict['secret'])

        LOG.debug(_("Request body: {0}").format(order_dict['secret']))

        resp = self.api.post(self.entity, order_dict)
        #TODO(dmend): return order object?
        order_id = resp['order_ref'].split('/')[-1]

        return order_id

    def get(self, order_id):
        """
        Returns an Order object

        :param order_id: The UUID of the order
        """
        LOG.debug(_("Getting order - Order ID: {0}").format(order_id))
        if not order_id:
            raise ValueError('order_id is required.')
        path = '{0}/{1}'.format(self.entity, order_id)
        resp = self.api.get(path)
        return Order(resp)

    def delete(self, order_id):
        """
        Deletes an order

        :param order_id: The UUID of the order
        """
        if not order_id:
            raise ValueError('order_id is required.')
        path = '{0}/{1}'.format(self.entity, order_id)
        self.api.delete(path)

    def list(self, limit=10, offset=0):
        params = {'limit': limit, 'offset': offset}
        resp = self.api.get(self.entity, params)

        return [Order(o) for o in resp['orders']]
