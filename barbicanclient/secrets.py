from urlparse import urlparse

from openstack.common import log as logging
from openstack.common.timeutils import parse_isotime

from barbicanclient import base


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
        self.mode = secret_dict.get('cypher_type')

        self.content_types = secret_dict.get('content_types')
        self.id = urlparse(self.secret_ref).path.split('/').pop()

    def __str__(self):
        return ("Secret - ID: {0}\n"
                "         href: {1}\n"
                "         name: {2}\n"
                "         created: {3}\n"
                "         status: {4}\n"
                "         content types: {5}\n"
                "         algorithm: {6}\n"
                "         bit length: {7}\n"
                "         mode: {8}\n"
                "         expiration: {9}\n"
                .format(self.id, self.secret_ref, self.name, self.created,
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
        Stores a new secret in Barbican

        :param name: A friendly name for the secret
        :param payload: The unencrypted secret data
        :param payload_content_type: The format/type of the secret data
        :param payload_content_encoding: The encoding of the secret data
        :param algorithm: The algorithm barbican should use to encrypt
        :param bit_length: The bit length of the key used for ecnryption
        :param mode: The algorithm mode (e.g. CBC or CTR mode)
        :param expiration: The expiration time of the secret in ISO 8601 format
        :returns: Secret ID for the stored secret
        """
        LOG.debug("Creating secret of payload content type {0}".format(
            payload_content_type))
        href = self.entity
        LOG.debug("href: {0}".format(href))

        secret_dict = dict()
        secret_dict['name'] = name
        secret_dict['payload'] = payload
        secret_dict['payload_content_type'] = payload_content_type
        secret_dict['payload_content_encoding'] = payload_content_encoding
        secret_dict['algorithm'] = algorithm
        #TODO(dmend): Change this to 'mode'
        secret_dict['cypher_type'] = mode
        secret_dict['bit_length'] = bit_length
        secret_dict['expiration'] = expiration
        self._remove_empty_keys(secret_dict)

        LOG.debug("Request body: {0}".format(secret_dict))

        resp = self.api.post(self.entity, secret_dict)
        #TODO(dmend): return secret object?
        #secret = Secret(resp)
        secret_id = resp['secret_ref'].split('/')[-1]

        return secret_id

    def get(self, secret_id):
        """
        Returns a Secret object with information about the secret.

        :param secret_id: The UUID of the secret
        """
        if not secret_id:
            raise ValueError('secret_id is required.')
        path = '{0}/{1}'.format(self.entity, secret_id)
        resp = self.api.get(path)
        return Secret(resp)

    def raw(self, secret_id, content_type):
        """
        Returns the actual secret data stored in Barbican.

        :param secret_id: The UUID of the secret
        :param content_type: The content_type of the secret
        :returns: secret data
        """
        if not all([secret_id, content_type]):
            raise ValueError('secret_id and content_type are required.')
        path = '{0}/{1}'.format(self.entity, secret_id)
        headers = {'Accept': content_type}
        return self.api.get_raw(path, headers)

    def delete(self, secret_id):
        """
        Deletes a secret

        :param secret_id: The UUID of the secret
        """
        if not secret_id:
            raise ValueError('secret_id is required.')
        path = '{0}/{1}'.format(self.entity, secret_id)
        self.api.delete(path)

    def list(self, limit=10, offset=0):

        LOG.debug('Listing secrets - offset {0} limit {1}'.format(offset,
                                                                  limit))
        params = {'limit': limit, 'offset': offset}
        resp = self.api.get(self.entity, params)

        return [Secret(s) for s in resp['secrets']]
