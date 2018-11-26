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
               "Type",
               "Container href",
               "Secret href",
               "Created",
               "Status",
               "Error code",
               "Error message"
               )

    def _get_formatted_data(self):
        created = self.created.isoformat() if self.created else None
        data = (self.order_ref,
                "Key",
                "N/A",
                self.secret_ref,
                created,
                self.status,
                self.error_status_code,
                self.error_reason
                )
        return data


class AsymmetricOrderFormatter(formatter.EntityFormatter):

    columns = ("Order href",
               "Type",
               "Container href",
               "Secret href",
               "Created",
               "Status",
               "Error code",
               "Error message"
               )

    def _get_formatted_data(self):
        created = self.created.isoformat() if self.created else None
        data = (self.order_ref,
                "Asymmetric",
                self.container_ref,
                "N/A",
                created,
                self.status,
                self.error_status_code,
                self.error_reason
                )
        return data


class CertificateOrderFormatter(formatter.EntityFormatter):

    columns = ("Order href",
               "Type",
               "Container href",
               "Secret href",
               "Created",
               "Status",
               "Error code",
               "Error message"
               )

    def _get_formatted_data(self):
        created = self.created.isoformat() if self.created else None
        data = (self.order_ref,
                "Certificate",
                self.container_ref,
                "N/A",
                created,
                self.status,
                self.error_status_code,
                self.error_reason
                )
        return data


@six.add_metaclass(abc.ABCMeta)
class Order(object):
    """Base order object to hold common functionality

    This should be considered an abstract class that should not be
    instantiated directly.
    """
    _entity = 'orders'

    def __init__(self, api, type, status=None, created=None, updated=None,
                 meta=None, order_ref=None, error_status_code=None,
                 error_reason=None, sub_status=None, sub_status_message=None,
                 creator_id=None):
        super(Order, self).__init__()

        self._api = api
        self._type = type
        self._status = status
        self._sub_status = sub_status
        self._sub_status_message = sub_status_message
        self._creator_id = creator_id

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
        """Submit the Order to Barbican.

        New Order objects are not persisted in Barbican until this method
        is called.
        """
        order_dict = {'type': self._type, 'meta': self._meta}
        LOG.debug("Request body: {0}".format(order_dict))
        response = self._api.post(self._entity, json=order_dict)
        if response:
            self._order_ref = response.get('order_ref')
        return self._order_ref

    def delete(self):
        """Deletes the Order from Barbican"""
        if self._order_ref:
            uuid_ref = base.calculate_uuid_ref(self._order_ref, self._entity)
            self._api.delete(uuid_ref)
            self._order_ref = None
        else:
            raise LookupError("Order is not yet stored.")


class KeyOrder(Order, KeyOrderFormatter):
    """KeyOrders can be used to request random key material from Barbican"""
    _type = 'key'
    _validMeta = (u'name', u'algorithm', u'mode', u'bit_length', u'expiration',
                  u'payload_content_type')

    def __init__(self, api, name=None, algorithm=None, bit_length=None,
                 mode=None, expiration=None, payload_content_type=None,
                 status=None, created=None, updated=None, order_ref=None,
                 secret_ref=None, error_status_code=None, error_reason=None,
                 sub_status=None, sub_status_message=None, creator_id=None):
        super(KeyOrder, self).__init__(
            api, self._type, status=status, created=created, updated=updated,
            meta={
                'name': name, 'algorithm': algorithm, 'bit_length': bit_length,
                'expiration': expiration,
                'payload_content_type': payload_content_type
            }, order_ref=order_ref, error_status_code=error_status_code,
            error_reason=error_reason, sub_status=sub_status,
            sub_status_message=sub_status_message, creator_id=creator_id)
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
                 mode=None, passphrase=None, pass_phrase=None, expiration=None,
                 payload_content_type=None, status=None, created=None,
                 updated=None, order_ref=None, container_ref=None,
                 error_status_code=None, error_reason=None, sub_status=None,
                 sub_status_message=None, creator_id=None):
        super(AsymmetricOrder, self).__init__(
            api, self._type, status=status, created=created, updated=updated,
            meta={
                'name': name, 'algorithm': algorithm, 'bit_length': bit_length,
                'expiration': expiration,
                'payload_content_type': payload_content_type
            }, order_ref=order_ref, error_status_code=error_status_code,
            error_reason=error_reason, sub_status=sub_status,
            sub_status_message=sub_status_message, creator_id=creator_id)
        self._container_ref = container_ref
        if passphrase:
            self._meta['pass_phrase'] = passphrase
        elif pass_phrase:
            # NOTE(jaosorior): Needed for backwards compatibility.
            # See bug #1635213
            self._meta['pass_phrase'] = pass_phrase

    @property
    def container_ref(self):
        return self._container_ref

    @property
    def pass_phrase(self):
        """Passphrase to be used for passphrase protected asymmetric keys"""
        return self._meta.get('pass_phrase')

    @pass_phrase.setter
    @immutable_after_save
    def pass_phrase(self, value):
        self._meta['pass_phrase'] = value

    def __repr__(self):
        return 'AsymmetricOrder(order_ref={0})'.format(self.order_ref)


class CertificateOrder(Order, CertificateOrderFormatter):
    _type = 'certificate'

    def __init__(self, api, name=None,
                 status=None, created=None, updated=None, order_ref=None,
                 container_ref=None, error_status_code=None, error_reason=None,
                 sub_status=None, sub_status_message=None, creator_id=None,
                 request_type=None, subject_dn=None,
                 source_container_ref=None, ca_id=None, profile=None,
                 request_data=None, requestor_name=None, requestor_email=None,
                 requestor_phone=None):
        super(CertificateOrder, self).__init__(
            api, self._type, status=status, created=created, updated=updated,
            meta={
                'name': name,
                'request_type': request_type,
                'subject_dn': subject_dn,
                'container_ref': source_container_ref,
                'ca_id': ca_id,
                'profile': profile,
                'request_data': request_data,
                'requestor_name': requestor_name,
                'requestor_email': requestor_email,
                'requestor_phone': requestor_phone},
            order_ref=order_ref, error_status_code=error_status_code,
            error_reason=error_reason)
        self._container_ref = container_ref

    @property
    def container_ref(self):
        return self._container_ref

    def __repr__(self):
        return 'CertificateOrder(order_ref={0})'.format(self.order_ref)


class OrderManager(base.BaseEntityManager):
    """Entity Manager for Order entitites"""

    _order_type_to_class_map = {
        'key': KeyOrder,
        'asymmetric': AsymmetricOrder,
        'certificate': CertificateOrder
    }

    def __init__(self, api):
        super(OrderManager, self).__init__(api, 'orders')

    def get(self, order_ref):
        """Retrieve an existing Order from Barbican

        :param order_ref: Full HATEOAS reference to an Order, or a UUID
        :returns: An instance of the appropriate subtype of Order
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug("Getting order - Order href: {0}".format(order_ref))
        uuid_ref = base.calculate_uuid_ref(order_ref, self._entity)
        try:
            response = self._api.get(uuid_ref)
        except AttributeError:
            raise LookupError(
                'Order {0} could not be found.'.format(order_ref)
            )
        return self._create_typed_order(response)

    def _create_typed_order(self, response):
        resp_type = response.pop('type').lower()
        order_type = self._order_type_to_class_map.get(resp_type)

        if (resp_type == 'certificate' and
                'container_ref' in response.get('meta', ())):
            response['source_container_ref'] = response['meta'].pop(
                'container_ref')

        # validate key_order meta fields.
        if resp_type == 'key' and (
           set(response['meta'].keys()) - set(KeyOrder._validMeta)):
                invalidFields = ', '.join(
                                map(str, set(
                                    response['meta'].keys()) -
                                    set(KeyOrder._validMeta)))
                raise TypeError(
                    'Invalid KeyOrder meta field: [%s]' % invalidFields)

        response.update(response.pop('meta'))

        if order_type is not None:
            return order_type(self._api, **response)
        else:
            raise TypeError('Unknown Order type "{0}"'.format(order_type))

    def create(self, type=None, **kwargs):
        if not type:
            raise TypeError('No Order type provided')
        order_type = self._order_type_to_class_map.get(type.lower())
        if not order_type:
            raise TypeError('Unknown Order type "{0}"'.format(type))

        return order_type(self._api, **kwargs)

    def create_key(self, name=None, algorithm=None, bit_length=None, mode=None,
                   payload_content_type=None, expiration=None):
        """Factory method for `KeyOrder` objects

        `KeyOrder` objects returned by this method have not yet been submitted
        to the Barbican service.

        :param name: A friendly name for the secret to be created
        :param algorithm: The algorithm associated with this secret key
        :param bit_length: The bit length of this secret key
        :param mode: The algorithm mode used with this secret key
        :param payload_content_type: The format/type of the secret data
        :param expiration: The expiration time of the secret in ISO 8601 format
        :returns: KeyOrder
        :rtype: :class:`barbicanclient.v1.orders.KeyOrder`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        return KeyOrder(api=self._api, name=name,
                        algorithm=algorithm, bit_length=bit_length, mode=mode,
                        payload_content_type=payload_content_type,
                        expiration=expiration)

    def create_asymmetric(self, name=None, algorithm=None, bit_length=None,
                          pass_phrase=None, payload_content_type=None,
                          expiration=None):
        """Factory method for `AsymmetricOrder` objects

        `AsymmetricOrder` objects returned by this method have not yet been
        submitted to the Barbican service.

        :param name: A friendly name for the container to be created
        :param algorithm: The algorithm associated with this secret key
        :param bit_length: The bit length of this secret key
        :param pass_phrase: Optional passphrase
        :param payload_content_type: The format/type of the secret data
        :param expiration: The expiration time of the secret in ISO 8601 format
        :returns: AsymmetricOrder
        :rtype: :class:`barbicanclient.v1.orders.AsymmetricOrder`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        return AsymmetricOrder(api=self._api, name=name, algorithm=algorithm,
                               bit_length=bit_length, passphrase=pass_phrase,
                               payload_content_type=payload_content_type,
                               expiration=expiration)

    def create_certificate(self, name=None, request_type=None, subject_dn=None,
                           source_container_ref=None, ca_id=None,
                           profile=None, request_data=None):
        """Factory method for `CertificateOrder` objects

        `CertificateOrder` objects returned by this method have not yet been
        submitted to the Barbican service.

        :param name: A friendly name for the container to be created
        :param request_type: The type of the certificate request
        :param subject_dn: A subject for the certificate
        :param source_container_ref: A container with a public/private key pair
            to use as source for stored-key requests
        :param ca_id: The identifier of the CA to use
        :param profile: The profile of certificate to use
        :param request_data: The CSR content
        :returns: CertificateOrder
        :rtype: :class:`barbicanclient.v1.orders.CertificateOrder`
        """
        return CertificateOrder(api=self._api, name=name,
                                request_type=request_type,
                                subject_dn=subject_dn,
                                source_container_ref=source_container_ref,
                                ca_id=ca_id,
                                profile=profile,
                                request_data=request_data)

    def delete(self, order_ref):
        """Delete an Order from Barbican

        :param order_ref: Full HATEOAS reference to an Order, or a UUID
        """
        if not order_ref:
            raise ValueError('order_ref is required.')
        uuid_ref = base.calculate_uuid_ref(order_ref, self._entity)
        self._api.delete(uuid_ref)

    def list(self, limit=10, offset=0):
        """List Orders for the project

        This method uses the limit and offset parameters for paging.

        :param limit: Max number of orders returned
        :param offset: Offset orders to begin list
        :returns: list of Order objects
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Listing orders - offset {0} limit {1}'.format(offset,
                                                                 limit))
        params = {'limit': limit, 'offset': offset}
        response = self._api.get(self._entity, params=params)

        return [
            self._create_typed_order(o) for o in response.get('orders', [])
        ]
