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
import six

from barbicanclient._i18n import _LW
from barbicanclient import acls as acl_manager
from barbicanclient import base
from barbicanclient import exceptions
from barbicanclient import formatter


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
                 creator_id=None):
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
            creator_id=creator_id
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
            return {u'default': self.payload_content_type}
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
                LOG.warning(_LW("Secret does not contain a payload"))
                return None
        return self._payload

    @property
    def acls(self):
        """Get ACL settings for this secret."""
        if self.secret_ref and not self._acls:
            self._acls = self._acl_manager.get(self.secret_ref)
        return self._acls

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
            _LW('DEPRECATION WARNING: Manually setting the '
                'payload_content_type can lead to unexpected '
                'results.  It will be removed in a future release. '
                'See Launchpad Bug #1419166.')
        )
        self._payload_content_type = value

    @payload_content_encoding.setter
    @immutable_after_save
    def payload_content_encoding(self, value):
        LOG.warning(
            _LW('DEPRECATION WARNING: Manually setting the '
                'payload_content_encoding can lead to unexpected '
                'results.  It will be removed in a future release. '
                'See Launchpad Bug #1419166.')
        )
        self._payload_content_encoding = value

    def _fetch_payload(self):
        if not self.payload_content_type and not self.content_types:
            raise ValueError('Secret has no encrypted data to decrypt.')
        elif not self.payload_content_type:
            raise ValueError("Must specify decrypt content-type as "
                             "secret does not specify a 'default' "
                             "content-type.")
        headers = {'Accept': self.payload_content_type}

        if self._secret_ref[-1] != "/":
            payload_url = self._secret_ref + '/payload'
        else:
            payload_url = self._secret_ref + 'payload'
        payload = self._api._get_raw(payload_url, headers=headers)
        if self.payload_content_type == u'text/plain':
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

        if self.payload == '':
            raise exceptions.PayloadException("Invalid Payload: "
                                              "Cannot Be Empty String")

        if self.payload is not None and not isinstance(self.payload,
                                                       (six.text_type,
                                                        six.binary_type)):
            raise exceptions.PayloadException("Invalid Payload Type")

        if self.payload_content_type or self.payload_content_encoding:
            '''
            Setting the payload_content_type and payload_content_encoding
            manually is deprecated.  This clause of the if statement is here
            for backwards compatibility and should be removed in a future
            release.
            '''
            secret_dict['payload'] = self.payload
            secret_dict['payload_content_type'] = self.payload_content_type
            secret_dict['payload_content_encoding'] = (
                self.payload_content_encoding
            )
        elif type(self.payload) is six.binary_type:
            '''
            six.binary_type is stored as application/octet-stream
            and it is base64 encoded for a one-step POST
            '''
            secret_dict['payload'] = (
                base64.b64encode(self.payload)
            ).decode('UTF-8')
            secret_dict['payload_content_type'] = u'application/octet-stream'
            secret_dict['payload_content_encoding'] = u'base64'
        elif type(self.payload) is six.text_type:
            '''
            six.text_type is stored as text/plain
            '''
            secret_dict['payload'] = self.payload
            secret_dict['payload_content_type'] = u'text/plain'

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

        if type(self.payload) is six.binary_type:
            headers = {'content-type': "application/octet-stream"}
        elif type(self.payload) is six.text_type:
            headers = {'content-type': "text/plain"}
        else:
            raise exceptions.PayloadException("Invalid Payload Type")

        self._api.put(self._secret_ref,
                      headers=headers,
                      data=self.payload)

    def delete(self):
        """Deletes the Secret from Barbican"""
        if self._secret_ref:
            self._api.delete(self._secret_ref)
            self._secret_ref = None
        else:
            raise LookupError("Secret is not yet stored.")

    def _fill_from_data(self, name=None, expiration=None, algorithm=None,
                        bit_length=None, secret_type=None, mode=None,
                        payload=None, payload_content_type=None,
                        payload_content_encoding=None, created=None,
                        updated=None, content_types=None, status=None,
                        creator_id=None):
        self._name = name
        self._algorithm = algorithm
        self._bit_length = bit_length
        self._mode = mode
        self._secret_type = secret_type
        self._payload = payload
        self._payload_content_encoding = payload_content_encoding
        self._expiration = expiration
        self._creator_id = creator_id
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
            result = self._api.get(self._secret_ref)
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
                status=result.get('status')
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

        :param str secret_ref: Full HATEOAS reference to a Secret
        :param str payload_content_type: DEPRECATED: Content type to use for
            payload decryption. Setting this can lead to unexpected results.
            See Launchpad Bug #1419166.
        :returns: Secret object retrieved from Barbican
        :rtype: :class:`barbicanclient.secrets.Secret`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug("Getting secret - Secret href: {0}".format(secret_ref))
        base.validate_ref(secret_ref, 'Secret')
        return Secret(
            api=self._api,
            payload_content_type=payload_content_type,
            secret_ref=secret_ref
        )

    def update(self, secret_ref, payload=None):
        """Update an existing Secret from Barbican

        :param str secret_ref: Full HATEOAS reference to a Secret
        :param str payload: New payload to add to secret
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """

        base.validate_ref(secret_ref, 'Secret')
        if not secret_ref:
            raise ValueError('secret_ref is required.')

        if type(payload) is six.binary_type:
            headers = {'content-type': "application/octet-stream"}
        elif type(payload) is six.text_type:
            headers = {'content-type': "text/plain"}
        else:
            raise exceptions.PayloadException("Invalid Payload Type")

        self._api.put(secret_ref,
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
        :rtype: :class:`barbicanclient.secrets.Secret`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        return Secret(api=self._api, name=name, payload=payload,
                      payload_content_type=payload_content_type,
                      payload_content_encoding=payload_content_encoding,
                      algorithm=algorithm, bit_length=bit_length, mode=mode,
                      secret_type=secret_type, expiration=expiration)

    def delete(self, secret_ref):
        """Delete a Secret from Barbican

        :param secret_ref: The href for the secret to be deleted
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        base.validate_ref(secret_ref, 'Secret')
        if not secret_ref:
            raise ValueError('secret_ref is required.')
        self._api.delete(secret_ref)

    def list(self, limit=10, offset=0, name=None, algorithm=None,
             mode=None, bits=0):
        """List Secrets for the project

        This method uses the limit and offset parameters for paging,
        and also supports filtering.

        :param limit: Max number of secrets returned
        :param offset: Offset secrets to begin list
        :param name: Name filter for the list
        :param algorithm: Algorithm filter for the list
        :param mode: Mode filter for the list
        :param bits: Bits filter for the list
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

        response = self._api.get(self._entity, params=params)

        return [
            Secret(api=self._api, **s)
            for s in response.get('secrets', [])
        ]
