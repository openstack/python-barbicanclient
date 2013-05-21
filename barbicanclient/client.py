
from eventlet.green.urllib import quote
import eventlet
eventlet.monkey_patch(socket=True, select=True)

import json
import requests

from barbicanclient.secrets import Secret
from barbicanclient.common.auth import authenticate
from barbicanclient.common.exceptions import ClientException
from urlparse import urljoin


class Connection(object):
    def __init__(self, auth_endpoint, user, key, tenant, **kwargs):
        """
        :param auth_endpoint: The auth URL to authenticate against
        :param user: The user to authenticate as
        :param key: The API key or passowrd to auth with
        """
        self._auth_endpoint = auth_endpoint
        self._user = user
        self._key = key
        self._tenant = tenant
        self._endpoint = kwargs.get('endpoint') or 'https://barbican.api.rackspacecloud.com/v1/'
        self._cacert = kwargs.get('cacert')

        self.connect()

        # Hardcoded uri's right now
        self.secrets_href = 'secrets/'

    @property
    def _conn(self):
        """
        Property to enable decorators to work
        properly
        """
        return self

    @property
    def auth_endpoint(self):
        """The fully-qualified URI of the auth endpoint"""
        return self._auth_endpoint

    @property
    def endpoint(self):
        """The fully-qualified URI of the endpoint"""
        return self._endpoint

    def connect(self, token=None):
        """
        Establishes a connection. If token is not None the
        token will be used for this connection and auth will
        not happen.
        """
        self._session = requests.Session()

        #headers = {"Client-Id": self._client_id}
        #self._session.headers.update(headers)
        self._session.verify = True

        if token:
            self.auth_token = token
        else:
            (self._endpoint,
             self.auth_token) = authenticate(self._auth_endpoint, self._user, self._key, self._tenant,
                                             endpoint=self._endpoint, cacert=self._cacert)

    @property
    def auth_token(self):
        try:
            return self._session.headers['X-Auth-Token']
        except KeyError:
            return None

    @auth_token.setter
    def auth_token(self, value):
        self._token = value
        self._session.headers['X-Auth-Token'] = value

    def list_secrets(self):
        """
        Returns the list of secrets for the auth'd tenant
        """
        #href = proc_template(self.secrets_href)
        href = "%s/%s" % (self._tenant, self.secrets_href)
        hdrs, body = self._perform_http(href=href, method='GET')

        secrets_dict = body['secrets']
        secrets = []
        for s in secrets_dict:
            secrets.append(Secret(self._conn, s))

        return secrets

    #
    # def create_queue(self, queue_name):
    #     """
    #     Creates a queue with the specified name
    #
    #     :param queue_name: The name of the queue
    #     :param ttl: The default time-to-live for messages in this queue
    #     """
    #     href = proc_template(self.queue_href, queue_name=queue_name)
    #     body = {}
    #
    #     self._perform_http(href=href, method='PUT', request_body=body)
    #
    #     return Queue(self, href=href, name=queue_name, metadata=body)
    #
    # def get_queue(self, queue_name):
    #     """
    #     Gets a queue by name
    #
    #     :param queue_name: The name of the queue
    #     """
    #     href = proc_template(self.queue_href, queue_name=queue_name)
    #
    #     try:
    #         hdrs, body = self._perform_http(href=href, method='GET')
    #     except ClientException as ex:
    #         raise NoSuchQueueError(queue_name) if ex.http_status == 404 else ex
    #
    #     return Queue(self, href=href, name=queue_name, metadata=body)
    #
    # def get_queues(self):
    #     href = self.queues_href
    #
    #     hdrs, res = self._perform_http(href=href, method='GET')
    #     queues = res["queues"]
    #
    #     for queue in queues:
    #         yield Queue(conn=self._conn, name=queue['name'],
    #                     href=queue['href'], metadata=queue['metadata'])
    #
    # def delete_queue(self, queue_name):
    #     """
    #     Deletes a queue
    #
    #     :param queue_name: The name of the queue
    #     """
    #     href = proc_template(self.queue_href, queue_name=queue_name)
    #     self._perform_http(href=href, method='DELETE')
    #
    # def get_queue_metadata(self, queue_name):
    #     href = proc_template(self._queue_href, queue_name=queue_name)
    #
    #     try:
    #         return self._perform_http(conn, href, 'GET')
    #     except ClientException as ex:
    #         raise NoSuchQueueError(queue_name) if ex.http_status == 404 else ex

    def _perform_http(self, method, href, request_body='', headers={}):
        """
        Perform an HTTP operation, checking for appropriate
        errors, etc. and returns the response

        :param method: The http method to use (GET, PUT, etc)
        :param body: The optional body to submit
        :param headers: Any additional headers to submit
        :return: (headers, body)
        """
        if not isinstance(request_body, str):
            request_body = json.dumps(request_body)

        url = urljoin(self._endpoint, href)

        response = requests.request(method=method, url=url, data=request_body)

        #response = self._session.request(method=method, url=url,
        #                                 data=request_body, headers=headers)

        # Check if the status code is 2xx class
        if not response.ok:
            raise ClientException(href=href, method=method, http_status=response.status_code,
                                  http_response_content=response.content)

        resp_body = json.loads(response.content) if response.content else ''

        return response.headers, resp_body