import eventlet
eventlet.monkey_patch(socket=True, select=True)

import json
import requests


from barbicanclient.secrets import Secret
from barbicanclient.orders import Order
from barbicanclient.common.auth import authenticate
from barbicanclient.common.exceptions import ClientException
from urlparse import urljoin


class Connection(object):
    SECRETS_PATH = 'secrets'
    ORDERS_PATH = 'orders'

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
        self._endpoint = (kwargs.get('endpoint')
                          or 'https://barbican.api.rackspacecloud.com/v1/')
        self._cacert = kwargs.get('cacert')

        self.connect()

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
            self._endpoint, self.auth_token = authenticate(
                self._auth_endpoint,
                self._user,
                self._key,
                self._tenant,
                endpoint=self._endpoint,
                cacert=self._cacert
            )

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
        href = "%s/%s?limit=100" % (self._tenant, self.SECRETS_PATH)
        hdrs, body = self._perform_http(href=href, method='GET')

        secrets_dict = body['secrets']
        secrets = []
        for s in secrets_dict:
            secrets.append(Secret(self._conn, s))

        return secrets

    def list_orders(self):
        """
        Returns the list of orders
        """
        href = "%s/%s?limit=100" % (self._tenant, self.ORDERS_PATH)
        hdrs, body = self._perform_http(href=href, method='GET')

        orders_dict = body['orders']
        orders = []
        for o in orders_dict:
            orders.append(Order(self._conn, o))

        return orders

    def create_order(self,
                     name,
                     mime_type,
                     algorithm,
                     bit_length,
                     cypher_type):
        href = "%s/%s" % (self._tenant, self.ORDERS_PATH)
        order_dict = {'secret': {}}
        order_dict['secret']['name'] = name
        order_dict['secret']['mime_type'] = mime_type
        order_dict['secret']['algorithm'] = algorithm
        order_dict['secret']['bit_length'] = bit_length
        order_dict['secret']['cypher_type'] = cypher_type
        hdrs, body = self._perform_http(href=href,
                                        method='POST',
                                        request_body=json.dumps(order_dict))
        return body['order_ref']

    def delete_order(self, order_id):
        href = "%s/%s/%s" % (self._tenant, self.ORDERS_PATH, order_id)
        hdrs, body = self._perform_http(href=href, method='DELETE')
        # TODO: should this return something

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
            raise ClientException(href=href, method=method,
                                  http_status=response.status_code,
                                  http_response_content=response.content)

        resp_body = json.loads(response.content) if response.content else ''

        return response.headers, resp_body
