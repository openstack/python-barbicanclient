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
import os

import requests

from barbicanclient.openstack.common import log as logging
from barbicanclient.openstack.common.gettextutils import _
from barbicanclient import orders
from barbicanclient import secrets


LOG = logging.getLogger(__name__)
logging.setup('barbicanclient')


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

    def __init__(self, auth_plugin=None, endpoint=None, tenant_id=None):
        """
        Barbican client object used to interact with barbican service.

        :param auth_plugin: Authentication backend plugin
            defaults to None
        :param endpoint: Barbican endpoint url.  Required when not using
            an auth_plugin.  When not provided, the client will try to
            fetch this from the auth service catalog
        :param tenant_id: The tenant ID used for context in barbican.
            Required when not using auth_plugin.  When not provided,
            the client will try to get this from the auth_plugin.
        """
        LOG.debug(_("Creating Client object"))

        self._session = requests.Session()
        self.auth_plugin = auth_plugin

        if self.auth_plugin is not None:
            self._barbican_url = self.auth_plugin.barbican_url
            self._tenant_id = self.auth_plugin.tenant_id
            self._session.headers.update(
                {'X-Auth-Token': self.auth_plugin.auth_token}
            )
        else:
            if endpoint is None:
                raise ValueError('Barbican endpoint url must be provided, or '
                                 'must be available from auth_plugin')
            if tenant_id is None:
                raise ValueError('Tenant ID must be provided, or must be'
                                 ' available from the auth_plugin')
            if endpoint.endswith('/'):
                self._barbican_url = endpoint[:-1]
            else:
                self._barbican_url = endpoint
            self._tenant_id = tenant_id

        self.base_url = '{0}/{1}'.format(self._barbican_url, self._tenant_id)
        self.secrets = secrets.SecretManager(self)
        self.orders = orders.OrderManager(self)

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
        if status >= 500:
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
