from urlparse import urlparse

from openstack.common import log as logging
from openstack.common.timeutils import parse_isotime

from barbicanclient import base


LOG = logging.getLogger(__name__)


class Secret(object):

    """
    A secret is any data the user has stored in the key management system.
    """

    def __init__(self, secret_dict):
        """
        Builds a secret object from a dictionary.
        """
        self.secret_ref = secret_dict.get('secret_ref')
        self.created = parse_isotime(secret_dict.get('created'))
        self.status = secret_dict.get('status')

        self.algorithm = secret_dict.get('algorithm')
        self.bit_length = secret_dict.get('bit_length')
        self.payload_content_type = secret_dict.get('payload_content_type')
        self.payload_content_encoding = secret_dict.get(
            'payload_content_encoding')

        self.cypher_type = secret_dict.get('cypher_type')
        self.name = secret_dict.get('name')

        if secret_dict.get('expiration') is not None:
            self.expiration = parse_isotime(secret_dict['expiration'])
        else:
            self.expiration = None

        if secret_dict.get('updated') is not None:
            self.updated = parse_isotime(secret_dict['updated'])
        else:
            self.updated = None

        self._id = urlparse(self.secret_ref).path.split('/').pop()

    @property
    def id(self):
        return self._id

    def __str__(self):
        return ("Secret - ID: {0}\n"
                "         reference: {1}\n"
                "         name: {2}\n"
                "         created: {3}\n"
                "         status: {4}\n"
                "         payload content type: {5}\n"
                "         payload content encoding: {6}\n"
                "         bit length: {7}\n"
                "         algorithm: {8}\n"
                "         cypher type: {9}\n"
                "         expiration: {10}\n"
                .format(self.id, self.secret_ref, self.name, self.created,
                        self.status, self.payload_content_type,
                        self.payload_content_encoding, self.bit_length,
                        self.algorithm, self.cypher_type, self.expiration)
                )


class SecretManager(base.BaseEntityManager):

    def __init__(self, api):
        super(SecretManager, self).__init__(api, 'secrets')

    def create(self,
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

    def list(self, limit=10, offset=0):

        LOG.debug('Listing secrets - offset {0} limit {1}'.format(offset,
                                                                  limit))
        params = {'limit': limit, 'offset': offset}
        resp = self.api.get(self.entity, params)

        return resp
