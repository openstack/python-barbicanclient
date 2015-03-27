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
import abc
import functools
import logging

from oslo_utils.timeutils import parse_isotime
import six

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


class KeyOrderFormatter(formatter.EntityFormatter):

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


class AsymmetricOrderFormatter(formatter.EntityFormatter):

    columns = ("Order href",
               "Container href",
               "Created",
               "Status",
               "Error code",
               "Error message"
               )

    def _get_formatted_data(self):
        data = (self.order_ref,
                self.container_ref,
                self.created,
                self.status,
                self.error_status_code,
                self.error_reason
                )
        return data


@six.add_metaclass(abc.ABCMeta)
class Order(object):
    """
    Base order object to hold common functionality

    This should be considered an abstract class that should not be
    instantiated directly.
    """
    _entity = 'orders'

    def __init__(self, api, type, status=None, created=None, updated=None,
                 meta=None, order_ref=None, error_status_code=None,
                 error_reason=None):
        super(Order, self).__init__()

        self._api = api
        self._type = type
        self._status = status

        if created:
            self._created = parse_isotime(created)
        else:
            self._created = None

        if updated:
            self._updated = parse_isotime(updated)
        else:
            self._updated = None

        self._order_ref = order_ref

        self._meta = base.filter_null_keys(meta)

        self._error_status_code = error_status_code
        self._error_reason = error_reason

        if 'expiration' in self._meta.keys():
            self._meta['expiration'] = parse_isotime(self._meta['expiration'])

    @property
    def name(self):
        return self._meta.get('name')

    @name.setter
    @immutable_after_save
    def name(self, value):
        self._meta['name'] = value

    @property
    def algorithm(self):
        return self._meta.get('algorithm')

    @algorithm.setter
    @immutable_after_save
    def algorithm(self, value):
        self._meta['algorithm'] = value

    @property
    def bit_length(self):
        return self._meta.get('bit_length')

    @bit_length.setter
    @immutable_after_save
    def bit_length(self, value):
        self._meta['bit_length'] = value

    @property
    def expiration(self):
        return self._meta.get('expiration')

    @expiration.setter
    @immutable_after_save
    def expiration(self, value):
        self._meta['expiration'] = value

    @property
    def payload_content_type(self):
        return self._meta.get('payload_content_type')

    @payload_content_type.setter
    @immutable_after_save
    def payload_content_type(self, value):
        self._meta['payload_content_type'] = value

    @property
    def order_ref(self):
        return self._order_ref

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

    @immutable_after_save
    def submit(self):
        """
        Submit the Order to Barbican.  New Order objects are not persisted
        in Barbican until this method is called.
        """
        order_dict = {'type': self._type, 'meta': self._meta}
        LOG.debug("Request body: {0}".format(order_dict))
        response = self._api._post(self._entity, order_dict)
        if response:
            self._order_ref = response.get('order_ref')
        return self._order_ref

    def delete(self):
        """
        Deletes the Order from Barbican
        """
        if self._order_ref:
            self._api._delete(self._order_ref)
            self._order_ref = None
        else:
            raise LookupError("Order is not yet stored.")


class KeyOrder(Order, KeyOrderFormatter):
    """
    KeyOrders can be used to request random key material from Barbican
    """
    _type = 'key'

    def __init__(self, api, name=None, algorithm=None, bit_length=None,
                 mode=None, expiration=None, payload_content_type=None,
                 status=None, created=None, updated=None, order_ref=None,
                 secret_ref=None, error_status_code=None, error_reason=None):
        super(KeyOrder, self).__init__(
            api, self._type, status=status, created=created, updated=updated,
            meta={
                'name': name, 'algorithm': algorithm, 'bit_length': bit_length,
                'expiration': expiration,
                'payload_content_type': payload_content_type
            }, order_ref=order_ref, error_status_code=error_status_code,
            error_reason=error_reason)
        self._secret_ref = secret_ref
        if mode:
            self._meta['mode'] = mode

    @property
    def mode(self):
        """Encryption mode being used with this key

        The mode could be set to "CBC" for example, when requesting a key that
        will be used for AES encryption in CBC mode.
        """
        return self._meta.get('mode')

    @property
    def secret_ref(self):
        return self._secret_ref

    @mode.setter
    @immutable_after_save
    def mode(self, value):
        self._meta['mode'] = value

    def __repr__(self):
        return 'KeyOrder(order_ref={0})'.format(self.order_ref)


class AsymmetricOrder(Order, AsymmetricOrderFormatter):
    _type = 'asymmetric'

    def __init__(self, api, name=None, algorithm=None, bit_length=None,
                 pass_phrase=None, expiration=None, payload_content_type=None,
                 status=None, created=None, updated=None, order_ref=None,
                 container_ref=None, error_status_code=None,
                 error_reason=None):
        super(AsymmetricOrder, self).__init__(
            api, self._type, status=status, created=created, updated=updated,
            meta={
                'name': name, 'algorithm': algorithm, 'bit_length': bit_length,
                'expiration': expiration,
                'payload_content_type': payload_content_type
            }, order_ref=order_ref, error_status_code=error_status_code,
            error_reason=error_reason)
        self._container_ref = container_ref
        if pass_phrase:
            self._meta['pass_phrase'] = pass_phrase

    @property
    def container_ref(self):
        return self._container_ref

    @property
    def pass_phrase(self):
        """Passphrase to be used for passphrase protected asymmetric keys
        """
        return self._meta.get('pass_phrase')

    @pass_phrase.setter
    @immutable_after_save
    def pass_phrase(self, value):
        self._meta['pass_phrase'] = value

    def __repr__(self):
        return 'AsymmetricOrder(order_ref={0})'.format(self.order_ref)


class OrderManager(base.BaseEntityManager):
    """
    Entity Manager for Order entitites
    """

    _order_type_to_class_map = {
        'key': KeyOrder,
        'asymmetric': AsymmetricOrder
    }

    def __init__(self, api):
        super(OrderManager, self).__init__(api, 'orders')

    def get(self, order_ref):
        """
        Retrieve an existing Order from Barbican

        :param order_ref: Full HATEOAS reference to an Order
        :returns: An instance of the appropriate subtype of Order
        """
        LOG.debug("Getting order - Order href: {0}".format(order_ref))
        base.validate_ref(order_ref, 'Order')
        try:
            response = self._api._get(order_ref)
        except AttributeError:
            raise LookupError(
                'Order {0} could not be found.'.format(order_ref)
            )
        return self._create_typed_order(response)

    def _create_typed_order(self, response):
        resp_type = response.pop('type').lower()
        order_type = self._order_type_to_class_map.get(resp_type)

        response.update(response.pop('meta'))

        if order_type is KeyOrder:
            return KeyOrder(self._api, **response)
        elif order_type is AsymmetricOrder:
            return AsymmetricOrder(self._api, **response)
        else:
            raise TypeError('Unknown Order type "{0}"'.format(order_type))

    def create(self, type=None, **kwargs):
        order_type = self._order_type_to_class_map.get(type.lower())
        if order_type is not None:
            return order_type(self._api, **kwargs)
        else:
            raise TypeError('Unknown Order type "{0}"'.format(type))

    def create_key(self, name=None, algorithm=None, bit_length=None, mode=None,
                   payload_content_type=None, expiration=None):
        """
        Factory method for `KeyOrder` objects

        `KeyOrder` objects returned by this method have not yet been submitted
        to the Barbican service.

        :param name: A friendly name for the secret to be created
        :param algorithm: The algorithm associated with this secret key
        :param bit_length: The bit length of this secret key
        :param mode: The algorithm mode used with this secret key
        :param payload_content_type: The format/type of the secret data
        :param expiration: The expiration time of the secret in ISO 8601 format
        :returns: KeyOrder
        :rtype: :class:`barbicanclient.orders.KeyOrder`
        """
        return KeyOrder(api=self._api, name=name,
                        algorithm=algorithm, bit_length=bit_length, mode=mode,
                        payload_content_type=payload_content_type,
                        expiration=expiration)

    def create_asymmetric(self, name=None, algorithm=None, bit_length=None,
                          pass_phrase=None, payload_content_type=None,
                          expiration=None):
        """
        Factory method for `AsymmetricOrder` objects

        `AsymmetricOrder` objects returned by this method have not yet been
        submitted to the Barbican service.

        :param name: A friendly name for the container to be created
        :param algorithm: The algorithm associated with this secret key
        :param bit_length: The bit length of this secret key
        :param pass_phrase: Optional passphrase
        :param payload_content_type: The format/type of the secret data
        :param expiration: The expiration time of the secret in ISO 8601 format
        :returns: AsymmetricOrder
        :rtype: :class:`barbicanclient.orders.AsymmetricOrder`
        """
        return AsymmetricOrder(api=self._api, name=name, algorithm=algorithm,
                               bit_length=bit_length, pass_phrase=pass_phrase,
                               payload_content_type=payload_content_type,
                               expiration=expiration)

    def delete(self, order_ref):
        """
        Delete an Order from Barbican

        :param order_ref: The href for the order
        """
        if not order_ref:
            raise ValueError('order_ref is required.')
        self._api._delete(order_ref)

    def list(self, limit=10, offset=0):
        """
        List Orders for the project

        This method uses the limit and offset parameters for paging.

        :param limit: Max number of orders returned
        :param offset: Offset orders to begin list
        :returns: list of Order objects
        """
        LOG.debug('Listing orders - offset {0} limit {1}'.format(offset,
                                                                 limit))
        href = '{0}/{1}'.format(self._api._base_url, self._entity)
        params = {'limit': limit, 'offset': offset}
        response = self._api._get(href, params)

        return [
            self._create_typed_order(o) for o in response.get('orders', [])
        ]
