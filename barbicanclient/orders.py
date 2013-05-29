from urlparse import urlparse
from openstack.common.timeutils import parse_isotime


class Order(object):

    def __init__(self, connection, dict):
        """
        Builds an order object from a json representation. Includes the
        connection object for subtasks.
        """
        self.connection = connection
        self.status = dict.get('status')
        self.secret = dict.get('secret')  # TODO: figure out what to do here
        self.secret_ref = dict.get('secret_ref')
        self.order_ref = dict.get('order_ref')
        self.created = parse_isotime(dict.get('created'))
        if dict.get('updated') is not None:
            self.updated = parse_isotime(dict['updated'])

        self._id = urlparse(self.order_ref).path.split('/').pop()

    @property
    def id(self):
        return self._id

    def save(self):
        self.connection.update_order(self)

    def delete(self):
        self.connection.delete_order(self)

    def __repr__(self):
        s = "<Order %s>" % self.id
        s += "\n  Status: %s" % self.status
        s += "\n  Secret: %s" % self.secret
        s += "\n  Secret ref: %s" % self.secret_ref
        s += "\n  Order ref: %s" % self.order_ref
        s += "\n  Created: %s" % self.created
        s += "\n  Updated: %s" % self.updated
        return s
