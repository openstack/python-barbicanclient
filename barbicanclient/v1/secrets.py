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
import base64
import functools
import logging

from oslo_utils.timeutils import parse_isotime

from barbicanclient import base
from barbicanclient import exceptions
from barbicanclient import formatter
from barbicanclient.v1 import acls as acl_manager


LOG = logging.getLogger(__name__)


def lazy(func):
    @functools.wraps(func)
    def wrapper(self, *args):
        self._fill_lazy_properties()
        return func(self, *args)
    return wrapper


def immutable_after_save(func):
    @functools.wraps(func)
    def wrapper(self, *args):
        if self._secret_ref:
            raise base.ImmutableException()
        return func(self, *args)
    return wrapper


class SecretConsumersFormatter(formatter.EntityFormatter):

    columns = ("Service",
               "Resource type",
               "Resource id",
               "Created"
               )

    def _get_formatted_data(self):
        data = (self.service,
                self.resource_type,
                self.resource_id,
                self.created
                )
        return data


class SecretConsumers(SecretConsumersFormatter):
    """Secrets consumers managed by Barbican

    Secrets might or might not have consumers.
    """

    def __init__(self, secret_ref, service, resource_type, resource_id,
                 created=None, updated=None, status=None):

        self.secret_ref = secret_ref
        self.service = service
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.created = created
        self.updated = updated
        self.status = status

    def __repr__(self):
        return ('SecretConsumers(secret_ref="{0}", service="{1}", '
                'resource_type="{2}", resource_id="{3}", '
                'created="{4}", updated="{5}", status="{6}")'
                .format(self.secret_ref, self.service,
                        self.resource_type, self.resource_id,
                        self.created, self.updated, self.status))


class SecretFormatter(formatter.EntityFormatter):

    columns = ("Secret href",
               "Name",
               "Created",
               "Status",
               "Content types",
               "Algorithm",
               "Bit length",
               "Secret type",
               "Mode",
               "Expiration",
               )

    def _get_formatted_data(self):
        created = self.created.isoformat() if self.created else None
        expiration = self.expiration.isoformat() if self.expiration else None
        data = (self.secret_ref,
                self.name,
                created,
                self.status,
                self.content_types,
                self.algorithm,
                self.bit_length,
                self.secret_type,
                self.mode,
                expiration,
                )
        return data


class Secret(SecretFormatter):
    """Secrets managed by Barbican

    Secrets represent keys, credentials, and other sensitive data that is
    stored by the Barbican service.
    """
    _entity = 'secrets'

    def __init__(self, api, name=None, expiration=None, algorithm=None,
                 bit_length=None, mode=None, payload=None,
                 payload_content_type=None, payload_content_encoding=None,
                 secret_ref=None, created=None, updated=None,
                 content_types=None, status=None, secret_type=None,
                 creator_id=None, consumers=None):
        """Secret objects should not be instantiated directly.

        You should use the `create` or `get` methods of the
        :class:`barbicanclient.secrets.SecretManager` instead.
        """
        self._api = api
        self._secret_ref = secret_ref
        self._fill_from_data(
            name=name,
            expiration=expiration,
            algorithm=algorithm,
            bit_length=bit_length,
            secret_type=secret_type,
            mode=mode,
            payload=payload,
            payload_content_type=payload_content_type,
            payload_content_encoding=payload_content_encoding,
            created=created,
            updated=updated,
            content_types=content_types,
            status=status,
            creator_id=creator_id,
            consumers=consumers
        )
        self._acl_manager = acl_manager.ACLManager(api)
        self._acls = None

    @property
    def secret_ref(self):
        return self._secret_ref

    @property
    @lazy
    def name(self):
        return self._name

    @property
    @lazy
    def expiration(self):
        return self._expiration

    @property
    @lazy
    def algorithm(self):
        return self._algorithm

    @property
    @lazy
    def bit_length(self):
        return self._bit_length

    @property
    @lazy
    def secret_type(self):
        return self._secret_type

    @property
    @lazy
    def mode(self):
        return self._mode

    @property
    @lazy
    def payload_content_encoding(self):
        return self._payload_content_encoding

    @property
    @lazy
    def created(self):
        return self._created

    @property
    @lazy
    def updated(self):
        return self._updated

    @property
    @lazy
    def content_types(self):
        if self._content_types:
            return self._content_types
        elif self._payload_content_type:
            return {'default': self.payload_content_type}
        return None

    @property
    @lazy
    def status(self):
        return self._status

    @property
    def payload_content_type(self):
        if not self._payload_content_type and self.content_types:
            self._payload_content_type = self.content_types.get('default')
        return self._payload_content_type

    @property
    def payload(self):
        """Lazy-loaded property that holds the unencrypted data"""
        if self._payload is None and self.secret_ref is not None:
            try:
                self._fetch_payload()
            except ValueError:
                LOG.warning("Secret does not contain a payload")
                return None
        return self._payload

    @property
    def acls(self):
        """Get ACL settings for this secret."""
        if self.secret_ref and not self._acls:
            self._acls = self._acl_manager.get(self.secret_ref)
        return self._acls

    @property
    @lazy
    def consumers(self):
        return self._consumers

    @consumers.setter
    def consumers(self, value):
        self._consumers = value

    @name.setter
    @immutable_after_save
    def name(self, value):
        self._name = value

    @expiration.setter
    @immutable_after_save
    def expiration(self, value):
        self._expiration = value

    @algorithm.setter
    @immutable_after_save
    def algorithm(self, value):
        self._algorithm = value

    @bit_length.setter
    @immutable_after_save
    def bit_length(self, value):
        self._bit_length = value

    @secret_type.setter
    @immutable_after_save
    def secret_type(self, value):
        self._secret_type = value

    @mode.setter
    @immutable_after_save
    def mode(self, value):
        self._mode = value

    @payload.setter
    def payload(self, value):
        self._payload = value

    @payload_content_type.setter
    @immutable_after_save
    def payload_content_type(self, value):
        LOG.warning(
            'DEPRECATION WARNING: Manually setting the '
            'payload_content_type can lead to unexpected '
            'results.  It will be removed in a future release. '
            'See Launchpad Bug #1419166.')
        self._payload_content_type = value

    @payload_content_encoding.setter
    @immutable_after_save
    def payload_content_encoding(self, value):
        LOG.warning(
            'DEPRECATION WARNING: Manually setting the '
            'payload_content_encoding can lead to unexpected '
            'results.  It will be removed in a future release. '
            'See Launchpad Bug #1419166.')
        self._payload_content_encoding = value

    def _fetch_payload(self):
        if not self.payload_content_type and not self.content_types:
            raise ValueError('Secret has no encrypted data to decrypt.')
        elif not self.payload_content_type:
            raise ValueError("Must specify decrypt content-type as "
                             "secret does not specify a 'default' "
                             "content-type.")
        headers = {'Accept': self.payload_content_type}

        uuid_ref = base.calculate_uuid_ref(self._secret_ref, self._entity)
        payload_url = uuid_ref + '/payload'
        payload = self._api._get_raw(payload_url, headers=headers)
        if self.payload_content_type == 'text/plain':
            self._payload = payload.decode('UTF-8')
        else:
            self._payload = payload

    @immutable_after_save
    def store(self):
        """Stores the Secret in Barbican.

        New Secret objects are not persisted in Barbican until this method
        is called.

        :raises: PayloadException
        """
        secret_dict = {
            'name': self.name,
            'algorithm': self.algorithm,
            'mode': self.mode,
            'bit_length': self.bit_length,
            'secret_type': self.secret_type,
            'expiration': self.expiration
        }

        if self.payload is not None:
            if not isinstance(self.payload, (str, bytes)):
                raise exceptions.PayloadException("Invalid Payload Type")

            if not len(self.payload):
                raise exceptions.PayloadException("Invalid Payload: "
                                                  "Cannot Be Empty String")

        if self.payload_content_type or self.payload_content_encoding:
            '''
            Setting the payload_content_type and payload_content_encoding
            manually is deprecated.  This clause of the if statement is here
            for backwards compatibility and should be removed in a future
            release.
            '''
            if type(self.payload) is bytes:
                secret_dict['payload'] = self.payload.decode('utf-8')
            else:
                secret_dict['payload'] = self.payload
            secret_dict['payload_content_type'] = self.payload_content_type
            secret_dict['payload_content_encoding'] = (
                self.payload_content_encoding
            )
        elif type(self.payload) is bytes:
            '''
            bytes is stored as application/octet-stream
            and it is base64 encoded for a one-step POST
            '''
            secret_dict['payload'] = (
                base64.b64encode(self.payload)
            ).decode('UTF-8')
            secret_dict['payload_content_type'] = 'application/octet-stream'
            secret_dict['payload_content_encoding'] = 'base64'
        elif type(self.payload) is str:
            '''
            str is stored as text/plain
            '''
            secret_dict['payload'] = self.payload
            secret_dict['payload_content_type'] = 'text/plain'

        secret_dict = base.filter_null_keys(secret_dict)
        LOG.debug("Request body: {0}".format(base.censored_copy(secret_dict,
                                                                ['payload'])))

        # Save, store secret_ref and return
        response = self._api.post(self._entity, json=secret_dict)
        if response:
            self._secret_ref = response.get('secret_ref')
        return self.secret_ref

    def update(self):
        """Updates the secret in Barbican."""

        if not self.payload:
            raise exceptions.PayloadException("Invalid or Missing Payload")
        if not self.secret_ref:
            raise LookupError("Secret is not yet stored.")

        if type(self.payload) is bytes:
            headers = {'content-type': "application/octet-stream"}
        elif type(self.payload) is str:
            headers = {'content-type': "text/plain"}
        else:
            raise exceptions.PayloadException("Invalid Payload Type")

        uuid_ref = base.calculate_uuid_ref(self._secret_ref, self._entity)
        self._api.put(uuid_ref,
                      headers=headers,
                      data=self.payload)

    def delete(self):
        """Deletes the Secret from Barbican"""
        if self._secret_ref:
            uuid_ref = base.calculate_uuid_ref(self._secret_ref, self._entity)
            self._api.delete(uuid_ref)
            self._secret_ref = None
        else:
            raise LookupError("Secret is not yet stored.")

    def _fill_from_data(self, name=None, expiration=None, algorithm=None,
                        bit_length=None, secret_type=None, mode=None,
                        payload=None, payload_content_type=None,
                        payload_content_encoding=None, created=None,
                        updated=None, content_types=None, status=None,
                        creator_id=None, consumers=None):
        self._name = name
        self._algorithm = algorithm
        self._bit_length = bit_length
        self._mode = mode
        self._secret_type = secret_type
        self._payload = payload
        self._payload_content_encoding = payload_content_encoding
        self._expiration = expiration
        self._creator_id = creator_id
        self._consumers = consumers or list()
        if not self._secret_type:
            self._secret_type = "opaque"
        if self._expiration:
            self._expiration = parse_isotime(self._expiration)
        if self._secret_ref:
            self._content_types = content_types
            self._status = status
            self._created = created
            self._updated = updated
            if self._created:
                self._created = parse_isotime(self._created)
            if self._updated:
                self._updated = parse_isotime(self._updated)
        else:
            self._content_types = None
            self._status = None
            self._created = None
            self._updated = None

        if not self._content_types:
            self._payload_content_type = payload_content_type
        else:
            self._payload_content_type = self._content_types.get('default',
                                                                 None)

    def _fill_lazy_properties(self):
        if self._secret_ref and not self._name:
            uuid_ref = base.calculate_uuid_ref(self._secret_ref, self._entity)
            result = self._api.get(uuid_ref)
            self._fill_from_data(
                name=result.get('name'),
                expiration=result.get('expiration'),
                algorithm=result.get('algorithm'),
                bit_length=result.get('bit_length'),
                secret_type=result.get('secret_type'),
                mode=result.get('mode'),
                payload_content_type=result.get('payload_content_type'),
                payload_content_encoding=result.get(
                    'payload_content_encoding'
                ),
                created=result.get('created'),
                updated=result.get('updated'),
                content_types=result.get('content_types'),
                status=result.get('status'),
                consumers=result.get('consumers', [])
            )

    def __repr__(self):
        if self._secret_ref:
            return 'Secret(secret_ref="{0}")'.format(self._secret_ref)
        return 'Secret(name="{0}")'.format(self._name)


class SecretManager(base.BaseEntityManager):
    """Entity Manager for Secret entities"""

    def __init__(self, api):
        super(SecretManager, self).__init__(api, 'secrets')

    def get(self, secret_ref, payload_content_type=None):
        """Retrieve an existing Secret from Barbican

        :param str secret_ref: Full HATEOAS reference to a Secret, or a UUID
        :param str payload_content_type: DEPRECATED: Content type to use for
            payload decryption. Setting this can lead to unexpected results.
            See Launchpad Bug #1419166.
        :returns: Secret object retrieved from Barbican
        :rtype: :class:`barbicanclient.v1.secrets.Secret`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug("Getting secret - Secret href: {0}".format(secret_ref))
        base.validate_ref_and_return_uuid(secret_ref, 'Secret')
        return Secret(
            api=self._api,
            payload_content_type=payload_content_type,
            secret_ref=secret_ref
        )

    def update(self, secret_ref, payload=None):
        """Update an existing Secret in Barbican

        :param str secret_ref: Full HATEOAS reference to a Secret, or a UUID
        :param str payload: New payload to add to secret
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """

        base.validate_ref_and_return_uuid(secret_ref, 'Secret')
        if not secret_ref:
            raise ValueError('secret_ref is required.')

        if type(payload) is bytes:
            headers = {'content-type': "application/octet-stream"}
        elif type(payload) is str:
            headers = {'content-type': "text/plain"}
        else:
            raise exceptions.PayloadException("Invalid Payload Type")

        uuid_ref = base.calculate_uuid_ref(secret_ref, self._entity)
        self._api.put(uuid_ref,
                      headers=headers,
                      data=payload)

    def create(self, name=None, payload=None,
               payload_content_type=None, payload_content_encoding=None,
               algorithm=None, bit_length=None, secret_type=None,
               mode=None, expiration=None):
        """Factory method for creating new `Secret` objects

        Secrets returned by this method have not yet been stored in the
        Barbican service.

        :param name: A friendly name for the Secret
        :param payload: The unencrypted secret data
        :param payload_content_type: DEPRECATED: The format/type of the secret
            data. Setting this can lead to unexpected results.  See Launchpad
            Bug #1419166.
        :param payload_content_encoding: DEPRECATED: The encoding of the secret
            data. Setting this can lead to unexpected results.  See Launchpad
            Bug #1419166.
        :param algorithm: The algorithm associated with this secret key
        :param bit_length: The bit length of this secret key
        :param mode: The algorithm mode used with this secret key
        :param secret_type: The secret type for this secret key
        :param expiration: The expiration time of the secret in ISO 8601 format
        :returns: A new Secret object
        :rtype: :class:`barbicanclient.v1.secrets.Secret`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        return Secret(api=self._api, name=name, payload=payload,
                      payload_content_type=payload_content_type,
                      payload_content_encoding=payload_content_encoding,
                      algorithm=algorithm, bit_length=bit_length, mode=mode,
                      secret_type=secret_type, expiration=expiration)

    def delete(self, secret_ref, force=False):
        """Delete a Secret from Barbican

        :param secret_ref: Full HATEOAS reference to a Secret, or a UUID
        :param force: When true, forces the deletion of secrets with consumers
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        base.validate_ref_and_return_uuid(secret_ref, 'Secret')
        if not secret_ref:
            raise ValueError('secret_ref is required.')
        secret_object = self.get(secret_ref=secret_ref)
        uuid_ref = base.calculate_uuid_ref(secret_ref, self._entity)
        # If secret has no consumers OR
        # if secret has consumers but force==True, then delete it.
        if not secret_object.consumers or force:
            self._api.delete(uuid_ref)
        else:
            raise ValueError(
                "Secret has consumers! Remove them first or use the force "
                "parameter to delete it.")

    def list(self, limit=10, offset=0, name=None, algorithm=None, mode=None,
             bits=0, secret_type=None, created=None, updated=None,
             expiration=None, sort=None):
        """List Secrets for the project

        This method uses the limit and offset parameters for paging,
        and also supports filtering.

        The time filters (created, updated, and expiration) are expected to
        be an ISO 8601 formatted string, which can be prefixed with comparison
        operators: 'gt:' (greater-than), 'gte:' (greater-than-or-equal), 'lt:'
        (less-than), or 'lte': (less-than-or-equal).

        :param limit: Max number of secrets returned
        :param offset: Offset secrets to begin list
        :param name: Name filter for the list
        :param algorithm: Algorithm filter for the list
        :param mode: Mode filter for the list
        :param bits: Bits filter for the list
        :param secret_type: Secret type filter for the list
        :param created: Created time filter for the list, an ISO 8601 format
            string, optionally prefixed with 'gt:', 'gte:', 'lt:', or 'lte:'
        :param updated: Updated time filter for the list, an ISO 8601 format
            string, optionally prefixed with 'gt:', 'gte:', 'lt:', or 'lte:'
        :param expiration: Expiration time filter for the list, an ISO 8601
            format string, optionally prefixed with 'gt:', 'gte:', 'lt:',
            or 'lte:'
        :param sort: Determines the sorted order of the returned list, a
            string of comma-separated sort keys ('created', 'expiration',
            'mode', 'name', 'secret_type', 'status', or 'updated') with a
            direction appended (':asc' or ':desc') to each key
        :returns: list of Secret objects that satisfy the provided filter
            criteria.
        :rtype: list
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Listing secrets - offset {0} limit {1}'.format(offset,
                                                                  limit))
        params = {'limit': limit, 'offset': offset}
        if name:
            params['name'] = name
        if algorithm:
            params['alg'] = algorithm
        if mode:
            params['mode'] = mode
        if bits > 0:
            params['bits'] = bits
        if secret_type:
            params['secret_type'] = secret_type
        if created:
            params['created'] = created
        if updated:
            params['updated'] = updated
        if expiration:
            params['expiration'] = expiration
        if sort:
            params['sort'] = sort

        response = self._api.get(self._entity, params=params)

        return [
            Secret(api=self._api, **s)
            for s in response.get('secrets', [])
        ]

    def _enforce_microversion(self):
        if self._api.microversion == "1.0":
            raise NotImplementedError(
                "Server does not support secret consumers.  Minimum "
                "key-manager microversion required: 1.1")

    def register_consumer(self, secret_ref, service, resource_type,
                          resource_id):
        """Add a consumer to the secret

        :param secret_ref: Full HATEOAS reference to a secret, or a UUID
        :param service: Name of the consuming service
        :param resource_type: Type of the consuming resource
        :param resource_id: ID of the consuming resource
        :returns: A secret object per the get() method
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        :raises NotImplementedError: When using microversion 1.0
        """
        LOG.debug('Creating consumer registration for secret '
                  '{0} of service {1} for resource type {2}'
                  'with resource id {3}'.format(secret_ref, service,
                                                resource_type, resource_id))
        self._enforce_microversion()
        secret_uuid = base.validate_ref_and_return_uuid(
            secret_ref, 'Secret')
        href = '{0}/{1}/consumers'.format(self._entity, secret_uuid)
        consumer_dict = dict()
        consumer_dict['service'] = service
        consumer_dict['resource_type'] = resource_type
        consumer_dict['resource_id'] = resource_id

        response = self._api.post(href, json=consumer_dict)
        return Secret(api=self._api, **response)

    def remove_consumer(self, secret_ref, service,
                        resource_type, resource_id):
        """Remove a consumer from the secret

        :param secret_ref: Full HATEOAS reference to a secret, or a UUID
        :param service: Name of the previously consuming service
        :param resource_type: type of the previously consuming resource
        :param resource_id: ID of the previously consuming resource
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Deleting consumer registration for secret '
                  '{0} of service {1} for resource type {2}'
                  'with resource id {3}'.format(secret_ref, service,
                                                resource_type, resource_id))
        self._enforce_microversion()
        secret_uuid = base.validate_ref_and_return_uuid(
            secret_ref, 'secret')
        href = '{0}/{1}/consumers'.format(self._entity, secret_uuid)
        consumer_dict = {
            'service': service,
            'resource_type': resource_type,
            'resource_id': resource_id
        }

        self._api.delete(href, json=consumer_dict)

    def list_consumers(self, secret_ref, limit=10, offset=0):
        """List consumers of the secret

        :param secret_ref: Full HATEOAS reference to a secret, or a UUID
        :param limit: Max number of consumers returned
        :param offset: Offset secrets to begin list
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Listing consumers of secret {0}'.format(secret_ref))
        self._enforce_microversion()
        secret_uuid = base.validate_ref_and_return_uuid(
            secret_ref, 'secret')
        href = '{0}/{1}/consumers'.format(self._entity, secret_uuid)

        params = {'limit': limit, 'offset': offset}
        response = self._api.get(href, params=params)

        return [
            SecretConsumers(secret_ref=secret_ref, **s)
            for s in response.get('consumers', [])
        ]
