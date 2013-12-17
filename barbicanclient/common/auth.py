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
import abc
import json
import logging

from keystoneclient.v2_0 import client as ksclient
from keystoneclient import exceptions
import requests


LOG = logging.getLogger(__name__)


class AuthException(Exception):
    """Raised when authorization fails."""
    pass


class AuthPluginBase(object):
    """Base class for Auth plugins."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def auth_token(self):
        """
        Returns a valid token to be used in X-Auth-Token header for
        api requests.
        """

    @abc.abstractproperty
    def barbican_url(self):
        """
        Returns the barbican endpoint url, including the version.
        """


class KeystoneAuthV2(AuthPluginBase):
    def __init__(self, auth_url='', username='', password='',
                 tenant_name='', tenant_id='', insecure=False, keystone=None):
        if not all([auth_url, username, password, tenant_name or tenant_id]):
            raise ValueError('Please provide auth_url, username, password,'
                             ' and tenant_id or tenant_name.')
        self._keystone = keystone or ksclient.Client(username=username,
                                                     password=password,
                                                     tenant_name=tenant_name,
                                                     auth_url=auth_url,
                                                     insecure=insecure)
        self._barbican_url = None
        #TODO(dmend): make these configurable
        self._service_type = 'keystore'
        self._endpoint_type = 'publicURL'

        self.tenant_name = self._keystone.tenant_name
        self.tenant_id = self._keystone.tenant_id

    @property
    def auth_token(self):
        return self._keystone.auth_token

    @property
    def barbican_url(self):
        if not self._barbican_url:
            try:
                self._barbican_url = self._keystone.service_catalog.url_for(
                    attr='region',
                    filter_value=self._keystone.region_name,
                    service_type=self._service_type,
                    endpoint_type=self._endpoint_type
                )
            except exceptions.EmptyCatalog:
                LOG.error('Keystone is reporting an empty catalog.')
                raise AuthException('Empty keystone catalog.')
            except exceptions.EndpointNotFound:
                LOG.error('Barbican endpoint not found in keystone catalog.')
                raise AuthException('Barbican endpoint not found.')
        return self._barbican_url


class RackspaceAuthV2(AuthPluginBase):
    def __init__(self, auth_url='', username='', api_key='', password=''):
        if not all([auth_url, username, api_key or password]):
            raise ValueError('Please provide auth_url, username, api_key or '
                             'password.')
        self._auth_url = auth_url
        self._username = username
        self._api_key = api_key
        self._password = password
        self._auth_token = None
        self._barbican_url = None
        self.tenant_id = None
        self._authenticate()

    @property
    def auth_token(self):
        return self._auth_token

    @property
    def barbican_url(self):
        return self._barbican_url

    def _authenticate(self):
        auth_url = '{0}/tokens'.format(self._auth_url)
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}
        if self._api_key:
            payload = self._authenticate_with_api_key()
        else:
            payload = self._authenticate_with_password()

        r = requests.post(auth_url, data=json.dumps(payload), headers=headers)

        try:
            r.raise_for_status()
        except requests.HTTPError:
            msg = 'HTTPError ({0}): Unable to authenticate with Rackspace.'
            msg = msg.format(r.status_code)
            LOG.error(msg)
            raise AuthException(msg)

        try:
            data = r.json()
        except ValueError:
            msg = 'Error parsing response from Rackspace Identity.'
            LOG.error(msg)
            raise AuthException(msg)
        else:
            #TODO(dmend): get barbican_url from catalog
            self._auth_token = data['access']['token']['id']
            self.tenant_id = data['access']['token']['tenant']['id']

    def _authenticate_with_api_key(self):
        return {
            'auth': {
                'RAX-KSKEY:apiKeyCredentials': {
                    'username': self._username,
                    'apiKey': self._api_key
                }
            }
        }

    def _authenticate_with_password(self):
        return {
            'auth': {
                'passwordCredentials': {
                    'username': self._username,
                    'password': self._password
                }
            }
        }
