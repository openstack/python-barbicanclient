from urlparse import urlparse
from openstack.common.timeutils import parse_isotime


class Secret(object):
    """
    A secret is any data the user has stored in the key management system.
    """
    def __init__(self, connection, secret_dict):
        """
        Builds a secret object from a json representation. Includes the
        connection object for subtasks.
        """
        self.connection = connection
        self.secret_ref = secret_dict['secret_ref']
        self.created = parse_isotime(secret_dict.get('created'))
        self.status = secret_dict.get('status')

        self.algorithm = secret_dict.get('algorithm')
        self.bit_length = secret_dict.get('bit_length')
        self.mime_type = secret_dict.get('mime_type')
        self.name = secret_dict.get('name')
        self.cypher_type = secret_dict.get('cypher_type')

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
                "         MIME type: {4}\n"
                "         status: {5}\n"
                "         bit length: {6}\n"
                "         algorithm: {7}\n"
                "         cypher type: {8}\n"
                .format(self.id, self.secret_ref, self.name, self.created,
                        self.mime_type, self.status, self.bit_length,
                        self.algorithm, self.cypher_type)
                )
