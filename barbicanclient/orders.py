from urlparse import urlparse
from openstack.common.timeutils import parse_isotime


class Order(object):

    def __init__(self, connection, order_dict):
        """
        Builds an order object from a json representation. Includes the
        connection object for subtasks.
        """
        self.connection = connection
        self.status = order_dict.get('status')
        self.secret = order_dict.get('secret')
        self.secret_ref = order_dict.get('secret_ref')
        self.order_ref = order_dict.get('order_ref')
        self.created = parse_isotime(order_dict.get('created'))
        if order_dict.get('updated') is not None:
            self.updated = parse_isotime(order_dict['updated'])
        else:
            self.updated = None

        self._id = urlparse(self.order_ref).path.split('/').pop()

    @property
    def id(self):
        return self._id

    def get_secret(self):
        return self.connection.get_secret(self.secret_ref)

    def save(self):
        self.connection.update_order(self)

    def delete(self):
        self.connection.delete_order(self)

    def __str__(self):
        return ("Order - ID: {0}\n"
                "        order reference: {1}\n"
                "        secret reference: {2}\n"
                "        created: {3}\n"
                "        status: {4}\n"
                .format(self.id, self.order_ref, self.secret_ref, self.created,
                        self.status)
                )
