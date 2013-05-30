import eventlet
eventlet.monkey_patch(socket=True, select=True)

import json
import requests


from barbicanclient.secrets import Secret
from barbicanclient.orders import Order
from barbicanclient.common.auth import authenticate
from barbicanclient.common.exceptions import ClientException
from openstack.common.timeutils import parse_isotime
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
        href = "{0}/{1}?limit=100".format(self._tenant, self.SECRETS_PATH)
        hdrs, body = self._perform_http(href=href, method='GET')

        secrets_dict = body['secrets']
        secrets = []
        for s in secrets_dict:
            secrets.append(Secret(self._conn, s))

        return secrets

    def create_secret(self,
                      name,
                      mime_type,
                      algorithm,
                      bit_length,
                      cypher_type,
                      plain_text,
                      expiration):
        href = "{0}/{1}".format(self._tenant, self.SECRETS_PATH)
        secret_dict = {}
        secret_dict['name'] = name
        secret_dict['mime_type'] = mime_type
        secret_dict['algorithm'] = algorithm
        secret_dict['bit_length'] = int(bit_length)
        secret_dict['cypher_type'] = cypher_type
        secret_dict['plain_text'] = plain_text
        if expiration is not None:
            secret_dict['expiration'] = parse_isotime(expiration)
        hdrs, body = self._perform_http(href=href,
                                        method='POST',
                                        request_body=json.dumps(secret_dict))
        return body['secret_ref']

    def delete_secret(self, secret_id):
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        hdrs, body = self._perform_http(href=href, method='DELETE')
        # TODO: should this return something

    def get_secret(self, secret_id):
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        hdrs, body = self._perform_http(href=href, method='GET')

        return Secret(self._conn, body)

    def get_raw_secret(self, secret_id, mime_type):
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        hdrs = {"Accept": mime_type}
        hdrs, body = self._perform_http(href=href, method='GET', headers=hdrs,
                                        parse_json=False)

        return body

    def list_orders(self):
        """
        Returns the list of orders
        """
        href = "{0}/{1}?limit=100".format(self._tenant, self.ORDERS_PATH)
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
        href = "{0}/{1}".format(self._tenant, self.ORDERS_PATH)
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
        href = "{0}/{1}/{2}".format(self._tenant, self.ORDERS_PATH, order_id)
        hdrs, body = self._perform_http(href=href, method='DELETE')
        # TODO: should this return something

    def get_order(self, order_id):
        href = "{0}/{1}/{2}".format(self._tenant, self.ORDERS_PATH, order_id)
        hdrs, body = self._perform_http(href=href, method='GET')

        return Order(self._conn, body)

    def _perform_http(self, method, href, request_body='', headers={},
                      parse_json=True):
        """
        Perform an HTTP operation, checking for appropriate
        errors, etc. and returns the response

        :param method: The http method to use (GET, PUT, etc)
        :param body: The optional body to submit
        :param headers: Any additional headers to submit
        :param parse_json: Whether the response body should be parsed as json
        :return: (headers, body)
        """
        if not isinstance(request_body, str):
            request_body = json.dumps(request_body)

        url = urljoin(self._endpoint, href)

        response = requests.request(method=method, url=url, data=request_body,
                                    headers=headers)

        # Check if the status code is 2xx class
        if not response.ok:
            raise ClientException(href=href, method=method,
                                  http_status=response.status_code,
                                  http_response_content=response.content)

        if response.content and parse_json is True:
            resp_body = json.loads(response.content)
        elif response.content and parse_json is False:
            resp_body = response.content
        else:
            resp_body = ''

        return response.headers, resp_body
