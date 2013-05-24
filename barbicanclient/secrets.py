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
        self._href = dict['secret_ref']
        self._created = parse_isotime(dict['created'])
        self._status = dict['status']

        self._algorithm = dict.get('algorithm')
        self._bit_length = dict.get('bit_length')
        self._mime_type = dict.get('mime_type')
        self._name = dict.get('name')
        self._cypher_type = dict.get('cypher_type')

        if dict.get('expiration') is not None:
            self._expiration = parse_isotime(dict['expiration'])

        if dict.get('updated') is not None:
            self._updated = parse_isotime(dict['updated'])

        self._id = urlparse(self._href).path.split('/').pop()

    @property
    def id(self):
        return self._id

    def __repr__(self):
        return "<Secret %s>" % self.id
