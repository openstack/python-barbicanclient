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
from barbicanclient import base
from barbicanclient.openstack.common import log as logging
from barbicanclient.openstack.common.timeutils import parse_isotime


LOG = logging.getLogger(__name__)


class Secret(object):
    """
    Secrets are used to keep track of the data stored in Barbican.
    """

    def __init__(self, secret_dict):
        """
        Builds a secret object from a dictionary.
        """
        self.secret_ref = secret_dict.get('secret_ref')
        self.name = secret_dict.get('name')
        self.status = secret_dict.get('status')
        self.content_types = secret_dict.get('content_types')

        self.created = parse_isotime(secret_dict.get('created'))
        if secret_dict.get('expiration') is not None:
            self.expiration = parse_isotime(secret_dict['expiration'])
        else:
            self.expiration = None
        if secret_dict.get('updated') is not None:
            self.updated = parse_isotime(secret_dict['updated'])
        else:
            self.updated = None

        self.algorithm = secret_dict.get('algorithm')
        self.bit_length = secret_dict.get('bit_length')
        self.mode = secret_dict.get('mode')

    def __str__(self):
        return ("Secret - href: {0}\n"
                "         name: {1}\n"
                "         created: {2}\n"
                "         status: {3}\n"
                "         content types: {4}\n"
                "         algorithm: {5}\n"
                "         bit length: {6}\n"
                "         mode: {7}\n"
                "         expiration: {8}\n"
                .format(self.secret_ref, self.name, self.created,
                        self.status, self.content_types, self.algorithm,
                        self.bit_length, self.mode, self.expiration)
                )

    def __repr__(self):
        return 'Secret(name="{0}")'.format(self.name)


class SecretManager(base.BaseEntityManager):

    def __init__(self, api):
        super(SecretManager, self).__init__(api, 'secrets')

    def store(self,
              name=None,
              payload=None,
              payload_content_type=None,
              payload_content_encoding=None,
              algorithm=None,
              bit_length=None,
              mode=None,
              expiration=None):
        """
        Stores a new Secret in Barbican

        :param name: A friendly name for the secret
        :param payload: The unencrypted secret data
        :param payload_content_type: The format/type of the secret data
        :param payload_content_encoding: The encoding of the secret data
        :param algorithm: The algorithm associated with this secret key
        :param bit_length: The bit length of this secret key
        :param mode: The algorithm mode used with this secret key
        :param expiration: The expiration time of the secret in ISO 8601
                           format
        :returns: Secret href for the stored secret
        """
        LOG.debug("Creating secret of payload content type {0}".format(
            payload_content_type))

        secret_dict = dict()
        secret_dict['name'] = name
        secret_dict['payload'] = payload
        secret_dict['payload_content_type'] = payload_content_type
        secret_dict['payload_content_encoding'] = payload_content_encoding
        secret_dict['algorithm'] = algorithm
        secret_dict['mode'] = mode
        secret_dict['bit_length'] = bit_length
        secret_dict['expiration'] = expiration
        self._remove_empty_keys(secret_dict)

        LOG.debug("Request body: {0}".format(secret_dict))

        resp = self.api.post(self.entity, secret_dict)
        return resp['secret_ref']

    def get(self, secret_ref):
        """
        Returns a Secret object with metadata about the secret.

        :param secret_ref: The href for the secret
        """
        if not secret_ref:
            raise ValueError('secret_ref is required.')
        resp = self.api.get(secret_ref)
        return Secret(resp)

    def decrypt(self, secret_ref, content_type=None):
        """
        Returns the actual secret data stored in Barbican.

        :param secret_ref: The href for the secret
        :param content_type: The content_type of the secret, if not
            provided, the client will fetch the secret meta and use the
            default content_type to decrypt the secret
        :returns: secret data
        """
        if not secret_ref:
            raise ValueError('secret_ref is required.')
        if not content_type:
            secret = self.get(secret_ref)
            content_type = secret.content_types['default']
        headers = {'Accept': content_type}
        return self.api.get_raw(secret_ref, headers)

    def delete(self, secret_ref):
        """
        Deletes a secret

        :param secret_ref: The href for the secret
        """
        if not secret_ref:
            raise ValueError('secret_ref is required.')
        self.api.delete(secret_ref)

    def list(self, limit=10, offset=0):
        """
        List all secrets for the tenant

        :param limit: Max number of secrets returned
        :param offset: Offset secrets to begin list
        :returns: list of Secret metadata objects
        """
        LOG.debug('Listing secrets - offset {0} limit {1}'.format(offset,
                                                                  limit))
        href = '{0}/{1}'.format(self.api.base_url, self.entity)
        params = {'limit': limit, 'offset': offset}
        resp = self.api.get(href, params)

        return [Secret(s) for s in resp['secrets']]
