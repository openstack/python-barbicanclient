# Copyright (c) 2013 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import logging
import os

from keystoneclient.auth.base import BaseAuthPlugin
from keystoneclient import exceptions
from keystoneclient import session as ks_session

from barbicanclient.common.auth import KeystoneAuthPluginWrapper
from barbicanclient.openstack.common.gettextutils import _
from barbicanclient import orders
from barbicanclient import secrets
from barbicanclient import verifications


LOG = logging.getLogger(__name__)


class HTTPError(Exception):

    """Base exception for HTTP errors."""

    def __init__(self, message):
        super(HTTPError, self).__init__(message)


class HTTPServerError(HTTPError):

    """Raised for 5xx responses from the server."""
    pass


class HTTPClientError(HTTPError):

    """Raised for 4xx responses from the server."""
    pass


class HTTPAuthError(HTTPError):

    """Raised for 401 Unauthorized responses from the server."""
    pass


class Client(object):

    def __init__(self, session=None, auth_plugin=None, endpoint=None,
                 tenant_id=None, insecure=False, service_type='keystore',
                 interface='public'):
        """
        Barbican client object used to interact with barbican service.

        :param session: This can be either requests.Session or
            keystoneclient.session.Session
        :param auth_plugin: Authentication backend plugin
            defaults to None. This can also be a keystoneclient authentication
            plugin.
        :param endpoint: Barbican endpoint url.  Required when not using
            an auth_plugin.  When not provided, the client will try to
            fetch this from the auth service catalog
        :param tenant_id: The tenant ID used for context in barbican.
            Required when not using auth_plugin.  When not provided,
            the client will try to get this from the auth_plugin.
        :param insecure: Explicitly allow barbicanclient to perform
            "insecure" TLS (https) requests. The server's certificate
            will not be verified against any certificate authorities.
            This option should be used with caution.
        :param service_type: Used as an endpoint filter when using a
            keystone auth plugin. Defaults to 'keystore'
        :param interface: Another endpoint filter. Defaults to 'public'
        """
        LOG.debug(_("Creating Client object"))
        self._wrap_session_with_keystone_if_required(session, insecure)
        auth_plugin = self._update_session_auth_plugin(auth_plugin)

        if auth_plugin:
            self._barbican_url = self._session.get_endpoint(
                service_type=service_type, interface=interface)
            self._tenant_id = self._get_tenant_id(self._session, auth_plugin)
        else:
            # neither auth_plugin is provided nor it is available from session
            # fallback to passed in parameters
            self._validate_endpoint_and_tenant_id(endpoint, tenant_id)
            self._barbican_url = self._get_normalized_endpoint(endpoint)
            self._tenant_id = tenant_id

        self.base_url = '{0}/{1}'.format(self._barbican_url, self._tenant_id)
        self.secrets = secrets.SecretManager(self)
        self.orders = orders.OrderManager(self)
        self.verifications = verifications.VerificationManager(self)

    def _wrap_session_with_keystone_if_required(self, session, insecure):
        # if session is not a keystone session, wrap it
        if not isinstance(session, ks_session.Session):
            self._session = ks_session.Session(
                session=session, verify=not insecure)
        else:
            self._session = session

    def _update_session_auth_plugin(self, auth_plugin):
        # if auth_plugin is not provided and the session
        # has one, use it
        using_auth_from_session = False
        if auth_plugin is None and self._session.auth is not None:
            auth_plugin = self._session.auth
            using_auth_from_session = True

        ks_auth_plugin = auth_plugin
        # if auth_plugin is not a keystone plugin, wrap it
        if auth_plugin and not isinstance(auth_plugin, BaseAuthPlugin):
            ks_auth_plugin = KeystoneAuthPluginWrapper(auth_plugin)

        # if auth_plugin is provided, override the session's auth with it
        if not using_auth_from_session:
            self._session.auth = ks_auth_plugin

        return auth_plugin

    def _validate_endpoint_and_tenant_id(self, endpoint, tenant_id):
        if endpoint is None:
            raise ValueError('Barbican endpoint url must be provided, or '
                             'must be available from auth_plugin or '
                             'keystone_client')
        if tenant_id is None:
            raise ValueError('Tenant ID must be provided, or must be '
                             'available from the auth_plugin or '
                             'keystone-client')

    def _get_normalized_endpoint(self, endpoint):
        if endpoint.endswith('/'):
            endpoint = endpoint[:-1]
        return endpoint

    def _get_tenant_id(self, session, auth_plugin):
        if isinstance(auth_plugin, BaseAuthPlugin):
            # this is a keystoneclient auth plugin
            if hasattr(auth_plugin, 'get_access'):
                return auth_plugin.get_access(session).project_id
            else:
                # not an identity auth plugin and we don't know how to lookup
                # the tenant_id
                raise ValueError('Unable to obtain tenant_id from auth plugin')
        else:
            # this is a Barbican auth plugin
            return auth_plugin.tenant_id

    def get(self, href, params=None):
        headers = {'Accept': 'application/json'}
        resp = self._session.get(href, params=params, headers=headers)
        self._check_status_code(resp)
        return resp.json()

    def get_raw(self, href, headers):
        resp = self._session.get(href, headers=headers)
        self._check_status_code(resp)
        return resp.content

    def delete(self, href):
        resp = self._session.delete(href)
        self._check_status_code(resp)

    def post(self, path, data):
        url = '{0}/{1}/'.format(self.base_url, path)
        headers = {'content-type': 'application/json'}
        resp = self._session.post(url, data=json.dumps(data), headers=headers)
        self._check_status_code(resp)
        return resp.json()

    def _check_status_code(self, resp):
        status = resp.status_code
        LOG.debug('Response status {0}'.format(status))
        if status == 401:
            LOG.error('Auth error: {0}'.format(self._get_error_message(resp)))
            raise HTTPAuthError('{0}'.format(self._get_error_message(resp)))
        if not status or status >= 500:
            LOG.error('5xx Server error: {0}'.format(
                self._get_error_message(resp)
            ))
            raise HTTPServerError('{0}'.format(self._get_error_message(resp)))
        if status >= 400:
            LOG.error('4xx Client error: {0}'.format(
                self._get_error_message(resp)
            ))
            raise HTTPClientError('{0}'.format(self._get_error_message(resp)))

    def _get_error_message(self, resp):
        try:
            message = resp.json()['title']
        except ValueError:
            message = resp.content
        return message


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
