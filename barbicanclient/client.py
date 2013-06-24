import eventlet
eventlet.monkey_patch(socket=True, select=True)

import json
import os
import requests

from barbicanclient.secrets import Secret
from barbicanclient.orders import Order
from barbicanclient.common import auth
from barbicanclient.openstack.common import log
from barbicanclient.common.exceptions import ClientException
from barbicanclient.openstack.common.gettextutils import _
from openstack.common.timeutils import parse_isotime
from urlparse import urljoin


LOG = log.getLogger(__name__)
log.setup('barbicanclient')


class Connection(object):
    SECRETS_PATH = 'secrets'
    ORDERS_PATH = 'orders'

    def __init__(self, auth_endpoint=None, user=None, key=None, tenant=None,
                 token=None, **kwargs):
        """
        Authenticate and connect to the service endpoint, which can be
        received through authentication.

        Environment variables will be used by default when their corresponding
        arguments are not passed in.

        :param auth_endpoint: The auth URL to authenticate against
                              default: env('OS_AUTH_URL')
        :param user: The user to authenticate as
                     default: env('OS_USERNAME')
        :param key: The API key or password to auth with
                    default: env('OS_PASSWORD')
        :param tenant: The tenant ID
                       default: env('OS_TENANT_NAME')
        :keyword param endpoint: The barbican endpoint to connect to
                       default: env('BARBICAN_ENDPOINT')

        If a token is provided, an endpoint should be as well.
        """

        LOG.debug(_("Creating Connection object"))

        self.env = kwargs.get('fake_env') or env
        self._auth_endpoint = auth_endpoint or self.env('OS_AUTH_URL')
        self._user = user or self.env('OS_USERNAME')
        self._key = key or self.env('OS_PASSWORD')
        self._tenant = tenant or self.env('OS_TENANT_NAME')
        if not all([self._auth_endpoint, self._user, self._key, self._tenant]):
            raise ClientException("The authorization endpoint, username, key,"
                                  " and tenant name should either be passed i"
                                  "n or defined as environment variables.")
        self.authenticate = kwargs.get('authenticate') or auth.authenticate
        self.request = kwargs.get('request') or requests.request
        self._endpoint = (kwargs.get('endpoint') or
                          self.env('BARBICAN_ENDPOINT'))
        self._cacert = kwargs.get('cacert')
        self.connect(token=(token or self.env('AUTH_TOKEN')))

    @property
    def _conn(self):
        """Property to enable decorators to work properly"""
        return self

    @property
    def auth_endpoint(self):
        """The fully-qualified URI of the auth endpoint"""
        return self._auth_endpoint

    @property
    def endpoint(self):
        """The fully-qualified URI of the endpoint"""
        return self._endpoint

    @endpoint.setter
    def endpoint(self, value):
        self._endpoint = value

    def connect(self, token=None):
        """
        Establishes a connection. If token is not None or empty, it will be
        used for this connection, and authentication will not take place.

        :param token: An authentication token
        """

        LOG.debug(_("Establishing connection"))

        self._session = requests.Session()

        #headers = {"Client-Id": self._client_id}
        #self._session.headers.update(headers)
        self._session.verify = True

        if token:
            self.auth_token = token
        else:
            LOG.debug(_("Authenticating token"))
            endpoint, self.auth_token = self.authenticate(
                self._auth_endpoint,
                self._user,
                self._key,
                self._tenant,
                service_type='key-store',
                endpoint=self._endpoint,
                cacert=self._cacert
            )
            if self.endpoint is None:
                self.endpoint = endpoint

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

    def list_secrets(self, limit=10, offset=0):
        """
        Returns a tuple containing three items: a list of secrets pertaining
        to the given offset and limit, a reference to the previous set of
        secrets, and a reference to the next set of secrets. Either of the
        references may be None.

        :param limit: The limit to the number of secrets to list
        :param offset: The offset from the beginning to start listing
        """
        LOG.debug(_("Listing secrets - offset: {0}, limit: {1}").format(offset,
                                                                        limit))
        href = "{0}/{1}?limit={2}&offset={3}".format(self._tenant,
                                                     self.SECRETS_PATH,
                                                     limit, offset)
        return self.list_secrets_by_href(href)

    def list_secrets_by_href(self, href):
        """
        Returns a tuple containing three items: a list of secrets pertaining
        to the offset and limit within href, a reference to the previous set
        of secrets, and a reference to the next set of secrets. Either of the
        references may be None.

        :param href: The full secrets URI
        """
        LOG.debug(_("Listing secrets by href"))
        LOG.debug("href: {0}".format(href))
        if href is None:
            return [], None, None

        hdrs, body = self._perform_http(href=href, method='GET')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

        secrets_dict = body['secrets']
        secrets = [Secret(self._conn, s) for s in secrets_dict]

        prev_ref = body.get('previous')

        next_ref = body.get('next')

        return secrets, prev_ref, next_ref

    def create_secret(self,
                      mime_type,
                      plain_text=None,
                      name=None,
                      algorithm=None,
                      bit_length=None,
                      cypher_type=None,
                      expiration=None):
        """
        Creates and returns a Secret object with all of its metadata filled in.

        :param mime_type: The MIME type of the secret
        :param plain_text: The unencrypted secret
        :param name: A friendly name for the secret
        :param algorithm: The algorithm the secret is used with
        :param bit_length: The bit length of the secret
        :param cypher_type: The cypher type (e.g. block cipher mode)
        :param expiration: The expiration time of the secret in ISO 8601 format
        """
        LOG.debug(_("Creating secret of mime_type {0}").format(mime_type))
        href = "{0}/{1}".format(self._tenant, self.SECRETS_PATH)
        LOG.debug(_("href: {0}").format(href))
        secret_dict = {}
        secret_dict['mime_type'] = mime_type
        secret_dict['plain_text'] = plain_text
        secret_dict['name'] = name
        secret_dict['algorithm'] = algorithm
        secret_dict['cypher_type'] = cypher_type
        if bit_length is not None:
            secret_dict['bit_length'] = int(bit_length)
        if expiration is not None:
            secret_dict['expiration'] = parse_isotime(expiration)
        self._remove_empty_keys(secret_dict)
        LOG.debug(_("Request body: {0}").format(secret_dict))
        hdrs, body = self._perform_http(href=href,
                                        method='POST',
                                        request_body=json.dumps(secret_dict))

        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

        return self.get_secret(body['secret_ref'])

    def delete_secret_by_id(self, secret_id):
        """
        Deletes a secret

        :param secret_id: The UUID of the secret
        """
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        LOG.info(_("Deleting secret - Secret ID: {0}").format(secret_id))
        return self.delete_secret(href)

    def delete_secret(self, href):
        """
        Deletes a secret

        :param href: The full URI of the secret
        """
        hdrs, body = self._perform_http(href=href, method='DELETE')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

    def get_secret_by_id(self, secret_id):
        """
        Returns a Secret object

        :param secret_id: The UUID of the secret
        """
        LOG.debug(_("Getting secret - Secret ID: {0}").format(secret_id))
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        return self.get_secret(href)

    def get_secret(self, href):
        """
        Returns a Secret object

        :param href: The full URI of the secret
        """
        hdrs, body = self._perform_http(href=href, method='GET')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))
        return Secret(self._conn, body)

    def get_raw_secret_by_id(self, secret_id, mime_type):
        """
        Returns the raw secret

        :param secret_id: The UUID of the secret
        :param mime_type: The MIME type of the secret
        """
        LOG.debug(_("Getting raw secret - Secret ID: {0}").format(secret_id))
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        return self.get_raw_secret(href, mime_type)

    def get_raw_secret(self, href, mime_type):
        """
        Returns the raw secret

        :param href: The reference to the secret
        :param mime_type: The MIME type of the secret
        """
        hdrs = {"Accept": mime_type}
        hdrs, body = self._perform_http(href=href, method='GET', headers=hdrs,
                                        parse_json=False)
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))
        return body

    def list_orders(self, limit=10, offset=0):
        """
        Returns a tuple containing three items: a list of orders pertaining
        to the given offset and limit, a reference to the previous set of
        orders, and a reference to the next set of orders. Either of the
        references may be None.

        :param limit: The limit to the number of orders to list
        :param offset: The offset from the beginning to start listing
        """
        LOG.debug(_("Listing orders - offset: {0}, limit: {1}").format(offset,
                                                                       limit))
        href = "{0}/{1}?limit={2}&offset={3}".format(self._tenant,
                                                     self.ORDERS_PATH,
                                                     limit, offset)
        return self.list_orders_by_href(href)

    def list_orders_by_href(self, href):
        """
        Returns a tuple containing three items: a list of orders pertaining
        to the offset and limit within href, a reference to the previous set
        of orders, and a reference to the next set of orders. Either of the
        references may be None.

        :param href: The full orders URI
        """
        LOG.debug(_("Listing orders by href"))
        LOG.debug("href: {0}".format(href))
        if href is None:
            return [], None, None

        hdrs, body = self._perform_http(href=href, method='GET')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

        orders_dict = body['orders']
        orders = [Order(self._conn, o) for o in orders_dict]

        prev_ref = body.get('previous')

        next_ref = body.get('next')

        return orders, prev_ref, next_ref

    def create_order(self,
                     mime_type,
                     name=None,
                     algorithm=None,
                     bit_length=None,
                     cypher_type=None):
        """
        Creates and returns an Order object with all of its metadata filled in.

        :param mime_type: The MIME type of the secret
        :param name: A friendly name for the secret
        :param algorithm: The algorithm the secret is used with
        :param bit_length: The bit length of the secret
        :param cypher_type: The cypher type (e.g. block cipher mode)
        """
        LOG.debug(_("Creating order of mime_type {0}").format(mime_type))
        href = "{0}/{1}".format(self._tenant, self.ORDERS_PATH)
        LOG.debug("href: {0}".format(href))
        order_dict = {'secret': {}}
        order_dict['secret']['name'] = name
        order_dict['secret']['mime_type'] = mime_type
        order_dict['secret']['algorithm'] = algorithm
        order_dict['secret']['bit_length'] = bit_length
        order_dict['secret']['cypher_type'] = cypher_type
        self._remove_empty_keys(order_dict['secret'])
        LOG.debug(_("Request body: {0}").format(order_dict['secret']))
        hdrs, body = self._perform_http(href=href,
                                        method='POST',
                                        request_body=json.dumps(order_dict))

        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

        return self.get_order(body['order_ref'])

    def delete_order_by_id(self, order_id):
        """
        Deletes an order

        :param order_id: The UUID of the order
        """
        LOG.info(_("Deleting order - Order ID: {0}").format(order_id))
        href = "{0}/{1}/{2}".format(self._tenant, self.ORDERS_PATH, order_id)
        return self.delete_order(href)

    def delete_order(self, href):
        """
        Deletes an order

        :param href: The full URI of the order
        """
        hdrs, body = self._perform_http(href=href, method='DELETE')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

    def get_order_by_id(self, order_id):
        """
        Returns an Order object

        :param order_id: The UUID of the order
        """
        LOG.debug(_("Getting order - Order ID: {0}").format(order_id))
        href = "{0}/{1}/{2}".format(self._tenant, self.ORDERS_PATH, order_id)
        return self.get_order(href)

    def get_order(self, href):
        """
        Returns an Order object

        :param href: The full URI of the order
        """
        hdrs, body = self._perform_http(href=href, method='GET')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))
        return Order(self._conn, body)

    def _remove_empty_keys(self, dictionary):
        for k in dictionary.keys():
            if dictionary[k] is None:
                dictionary.pop(k)

    def _perform_http(self, method, href, request_body='', headers={},
                      parse_json=True):
        """
        Perform an HTTP operation, checking for appropriate
        errors, etc. and returns the response

        Returns the headers and body as a tuple.

        :param method: The http method to use (GET, PUT, etc)
        :param body: The optional body to submit
        :param headers: Any additional headers to submit
        :param parse_json: Whether the response body should be parsed as json
        """
        if not isinstance(request_body, str):
            request_body = json.dumps(request_body)

        if not self.endpoint.endswith('/'):
            self.endpoint += '/'

        url = urljoin(self.endpoint, href)

        headers['X-Auth-Token'] = self.auth_token

        response = self.request(method=method, url=url, data=request_body,
                                headers=headers)
        # Check if the status code is 2xx class
        if not response.ok:
            LOG.error('Bad response: {0}'.format(response.status_code))
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


def env(*vars, **kwargs):
    """Search for the first defined of possibly many env vars

    Returns the first environment variable defined in vars, or
    returns the default defined in kwargs.

    Source: Keystone's shell.py
    """
    for v in vars:
        value = os.environ.get(v, None)
        if value:
            return value
    return kwargs.get('default', '')
