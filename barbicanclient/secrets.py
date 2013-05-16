class Secret(object):
    """
    A secret is any data the user has stored in the key management system.
    """
    def __init__(self, connection, json):
        """
        Builds a secret object from a json representation. Includes the connection object for subtasks.
        """




    def __repr__(self):
        return "<Secret %s>" % self.name
