import eventlet
eventlet.monkey_patch(socket=True, select=True)

import json
import requests

from barbicanclient.common import config
from barbicanclient.secrets import Secret
from barbicanclient.orders import Order
from barbicanclient.common import auth
from barbicanclient.openstack.common import log
from barbicanclient.common.exceptions import ClientException
from barbicanclient.openstack.common.gettextutils import _
from openstack.common.timeutils import parse_isotime
from urlparse import urljoin


config.parse_args()
log.setup('barbicanclient')
LOG = log.getLogger(__name__)


class Connection(object):
    SECRETS_PATH = 'secrets'
    ORDERS_PATH = 'orders'

    def __init__(self, auth_endpoint, user, key, tenant,
                 token=None, authenticate=None, request=None, **kwargs):
        """
        :param auth_endpoint: The auth URL to authenticate against
        :param user: The user to authenticate as
        :param key: The API key or password to auth with
        """

        LOG.debug(_("Creating Connection object"))

        self._auth_endpoint = auth_endpoint
        self.authenticate = authenticate or auth.authenticate
        self.request = request or requests.request
        self._user = user
        self._key = key
        self._tenant = tenant
        self._endpoint = (kwargs.get('endpoint')
                          or 'https://barbican.api.rackspacecloud.com/v1/')
        self._cacert = kwargs.get('cacert')

        self.connect(token=token)

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

        LOG.debug(_("Establishing connection"))

        self._session = requests.Session()

        #headers = {"Client-Id": self._client_id}
        #self._session.headers.update(headers)
        self._session.verify = True

        if token:
            LOG.warn(_("Bypassing authentication - using provided token"))
            self.auth_token = token
        else:
            LOG.debug(_("Authenticating token"))
            self._endpoint, self.auth_token = self.authenticate(
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
        LOG.debug(_("Listing secrets"))
        href = "{0}/{1}?limit=100".format(self._tenant, self.SECRETS_PATH)
        LOG.debug("href: {0}".format(href))
        hdrs, body = self._perform_http(href=href, method='GET')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

        secrets_dict = body['secrets']
        secrets = []
        for s in secrets_dict:
            secrets.append(Secret(self._conn, s))

        return secrets

    def create_secret(self,
                      mime_type,
                      plain_text=None,
                      name=None,
                      algorithm=None,
                      bit_length=None,
                      cypher_type=None,
                      expiration=None):
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
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        LOG.info(_("Deleting secret - Secret ID: {0}").format(secret_id))
        return self.delete_secret(href)

    def delete_secret(self, href):
        hdrs, body = self._perform_http(href=href, method='DELETE')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

    def get_secret_by_id(self, secret_id):
        LOG.debug(_("Getting secret - Secret ID: {0}").format(secret_id))
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        return self.get_secret(href)

    def get_secret(self, href):
        hdrs, body = self._perform_http(href=href, method='GET')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))
        return Secret(self._conn, body)

    def get_raw_secret_by_id(self, secret_id, mime_type):
        LOG.debug(_("Getting raw secret - Secret ID: {0}").format(secret_id))
        href = "{0}/{1}/{2}".format(self._tenant, self.SECRETS_PATH, secret_id)
        return self.get_raw_secret(href, mime_type)

    def get_raw_secret(self, href, mime_type):
        hdrs = {"Accept": mime_type}
        hdrs, body = self._perform_http(href=href, method='GET', headers=hdrs,
                                        parse_json=False)
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))
        return body

    def list_orders(self):
        """
        Returns the list of orders
        """
        LOG.debug(_("Listing orders"))
        href = "{0}/{1}?limit=100".format(self._tenant, self.ORDERS_PATH)
        LOG.debug("href: {0}".format(href))
        hdrs, body = self._perform_http(href=href, method='GET')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

        orders_dict = body['orders']
        orders = []
        for o in orders_dict:
            orders.append(Order(self._conn, o))

        return orders

    def create_order(self,
                     mime_type,
                     name=None,
                     algorithm=None,
                     bit_length=None,
                     cypher_type=None):
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
        LOG.info(_("Deleting order - Order ID: {0}").format(order_id))
        href = "{0}/{1}/{2}".format(self._tenant, self.ORDERS_PATH, order_id)
        return self.delete_order(href)

    def delete_order(self, href):
        hdrs, body = self._perform_http(href=href, method='DELETE')
        LOG.debug(_("Response - headers: {0}\nbody: {1}").format(hdrs, body))

    def get_order_by_id(self, order_id):
        LOG.debug(_("Getting order - Order ID: {0}").format(order_id))
        href = "{0}/{1}/{2}".format(self._tenant, self.ORDERS_PATH, order_id)
        return self.get_order(href)

    def get_order(self, href):
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

        :param method: The http method to use (GET, PUT, etc)
        :param body: The optional body to submit
        :param headers: Any additional headers to submit
        :param parse_json: Whether the response body should be parsed as json
        :return: (headers, body)
        """
        if not isinstance(request_body, str):
            request_body = json.dumps(request_body)

        url = urljoin(self._endpoint, href)

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
