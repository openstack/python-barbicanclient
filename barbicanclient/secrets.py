from urlparse import urlparse
from openstack.common.timeutils import parse_isotime


class Secret(object):
    """
    A secret is any data the user has stored in the key management system.
    """
    def __init__(self, connection, dict):
        """
        Builds a secret object from a json representation. Includes the
        connection object for subtasks.
        """
        self._connection = connection
        self.secret_ref = dict['secret_ref']
        self.created = parse_isotime(dict['created'])
        self.status = dict['status']

        self.algorithm = dict.get('algorithm')
        self.bit_length = dict.get('bit_length')
        self.mime_type = dict.get('mime_type')
        self.name = dict.get('name')
        self.cypher_type = dict.get('cypher_type')

        if dict.get('expiration') is not None:
            self.expiration = parse_isotime(dict['expiration'])
        else:
            self.expiration = None

        if dict.get('updated') is not None:
            self.updated = parse_isotime(dict['updated'])
        else:
            self.updated = None

        self._id = urlparse(self.secret_ref).path.split('/').pop()

    @property
    def id(self):
        return self._id

    def __str__(self):
        return "<Secret %s>" % self.id
