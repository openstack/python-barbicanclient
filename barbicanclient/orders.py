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
import functools
import logging

from oslo.utils.timeutils import parse_isotime

from barbicanclient import base
from barbicanclient import formatter


LOG = logging.getLogger(__name__)


def immutable_after_save(func):
    @functools.wraps(func)
    def wrapper(self, *args):
        if self._order_ref:
            raise base.ImmutableException()
        return func(self, *args)
    return wrapper


class OrderFormatter(formatter.EntityFormatter):

    columns = ("Order href",
               "Secret href",
               "Created",
               "Status",
               "Error code",
               "Error message"
               )

    def _get_formatted_data(self):
        data = (self.order_ref,
                self.secret_ref,
                self.created,
                self.status,
                self.error_status_code,
                self.error_reason
                )
        return data


class Order(OrderFormatter):
    """
    Orders are used to request the generation of a Secret in Barbican.
    """
    _entity = 'orders'

    def __init__(self, api, name=None, algorithm=None, bit_length=None,
                 mode=None, payload_content_type='application/octet-stream',
                 order_ref=None, secret_ref=None, status=None,
                 created=None, updated=None, expiration=None,
                 error_status_code=None, error_reason=None, secret=None,
                 meta=None, type=None):
        self._api = api
        self._order_ref = order_ref
        self._type = type
        self._meta = meta
        if order_ref:
            self._error_status_code = error_status_code
            self._error_reason = error_reason
            self._status = status
            self._created = created
            self._updated = updated
            if self._created:
                self._created = parse_isotime(self._created)
            if self._updated:
                self._updated = parse_isotime(self._updated)
            self._secret_ref = secret_ref
            self._secret = secret
        else:
            self._error_status_code = None
            self._error_reason = None
            self._status = None
            self._created = None
            self._updated = None
            self._secret_ref = None
            self._secret = base.filter_empty_keys({
                'name': name,
                'algorithm': algorithm,
                'bit_length': bit_length,
                'mode': mode,
                'payload_content_type': payload_content_type,
                'expiration': expiration
            })
        if self._secret.get("expiration"):
            self._secret['expiration'] = parse_isotime(
                self._secret.get('expiration'))

    @property
    def name(self):
        return self._secret.get('name')

    @property
    def expiration(self):
        return self._secret.get('expiration')

    @property
    def algorithm(self):
        return self._secret.get('algorithm')

    @property
    def bit_length(self):
        return self._secret.get('bit_length')

    @property
    def mode(self):
        return self._secret.get('mode')

    @property
    def payload_content_type(self):
        return self._secret.get('payload_content_type')

    @property
    def order_ref(self):
        return self._order_ref

    @property
    def secret_ref(self):
        return self._secret_ref

    @property
    def created(self):
        return self._created

    @property
    def updated(self):
        return self._updated

    @property
    def status(self):
        return self._status

    @property
    def error_status_code(self):
        return self._error_status_code

    @property
    def error_reason(self):
        return self._error_reason

    @property
    def type(self):
        return self._type

    @property
    def meta(self):
        return self._meta

    @name.setter
    @immutable_after_save
    def name(self, value):
        self._secret['name'] = value

    @expiration.setter
    @immutable_after_save
    def expiration(self, value):
        self._secret['expiration'] = value

    @algorithm.setter
    @immutable_after_save
    def algorithm(self, value):
        self._secret['algorithm'] = value

    @bit_length.setter
    @immutable_after_save
    def bit_length(self, value):
        self._secret['bit_length'] = value

    @mode.setter
    @immutable_after_save
    def mode(self, value):
        self._secret['mode'] = value

    @payload_content_type.setter
    @immutable_after_save
    def payload_content_type(self, value):
        self._secret['payload_content_type'] = value

    @type.setter
    @immutable_after_save
    def type(self, value):
        self._type = value

    @meta.setter
    @immutable_after_save
    def meta(self, value):
        self._meta = value

    @immutable_after_save
    def submit(self):
        order_dict = dict({
            'secret': self._secret
        })
        LOG.debug("Request body: {0}".format(order_dict.get('secret')))
        response = self._api._post(self._entity, order_dict)
        if response:
            self._order_ref = response.get('order_ref')
        return self._order_ref

    def delete(self):
        if self._order_ref:
            self._api._delete(self._order_ref)
            self._order_ref = None
        else:
            raise LookupError("Order is not yet stored.")

    def __repr__(self):
        return 'Order(order_ref={0})'.format(self.order_ref)


class OrderManager(base.BaseEntityManager):

    def __init__(self, api):
        super(OrderManager, self).__init__(api, 'orders')

    def get(self, order_ref):
        """
        Get an Order

        :param order_ref: Full HATEOAS reference to an Order
        :returns: Order
        """
        LOG.debug("Getting order - Order href: {0}".format(order_ref))
        base.validate_ref(order_ref, 'Order')
        response = self._api._get(order_ref)
        return Order(api=self._api, **response)

    def create(self, name=None, payload_content_type=None,
               algorithm=None, bit_length=None, mode=None, expiration=None):
        """
        Create an Order

        :param name: A friendly name for the secret
        :param payload_content_type: The format/type of the secret data
        :param algorithm: The algorithm associated with this secret key
        :param bit_length: The bit length of this secret key
        :param mode: The algorithm mode used with this secret key
        :param expiration: The expiration time of the secret in ISO 8601 format
        :returns: Order
        """
        return Order(api=self._api, name=name,
                     payload_content_type=payload_content_type,
                     algorithm=algorithm, bit_length=bit_length, mode=mode,
                     expiration=expiration)

    def delete(self, order_ref):
        """
        Delete an Order

        :param order_ref: The href for the order
        """
        if not order_ref:
            raise ValueError('order_ref is required.')
        self._api._delete(order_ref)

    def list(self, limit=10, offset=0):
        """
        List all Orders for the tenant

        :param limit: Max number of orders returned
        :param offset: Offset orders to begin list
        :returns: list of Order objects
        """
        LOG.debug('Listing orders - offset {0} limit {1}'.format(offset,
                                                                 limit))
        href = '{0}/{1}'.format(self._api._base_url, self._entity)
        params = {'limit': limit, 'offset': offset}
        response = self._api._get(href, params)

        return [Order(api=self._api, **o) for o in response.get('orders', [])]
