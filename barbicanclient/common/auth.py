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
from keystoneclient.v2_0 import client as ksclient
from keystoneclient import exceptions


class AuthException(Exception):
    """Raised when authorization fails."""
    def __init__(self, message):
        self.message = message


class KeystoneAuthV2(object):
    def __init__(self, auth_url='', username='', password='',
                 tenant_name='', tenant_id=''):
        if not all([auth_url, username, password, tenant_name or tenant_id]):
            raise ValueError('Please provide auht_url, username, password,'
                             ' and tenant_id or tenant_name)')
        self._keystone = ksclient.Client(username=username,
                                         password=password,
                                         tenant_name=tenant_name,
                                         auth_url=auth_url)
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
