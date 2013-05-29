class ClientException(Exception):
    """Exception for wrapping up Barbican client errors"""
    def __init__(self, href='', http_status=0,
                 method='', http_response_content=''):

        self.method = method
        self.href = href
        self.http_status = http_status
        self.http_response_content = http_response_content

        msg = "%s %s returned %d with msg: %s" % (self.method,
                                                  self.href,
                                                  self.http_status,
                                                  self.http_response_content)
        Exception.__init__(self, msg)
