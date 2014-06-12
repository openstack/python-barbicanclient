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

from keystoneclient.auth.base import BaseAuthPlugin
from keystoneclient.v2_0 import client as ksclient
from keystoneclient import exceptions
from keystoneclient import session as ks_session
from keystoneclient import discover
import requests
import six


LOG = logging.getLogger(__name__)


class KeystoneAuthPluginWrapper(BaseAuthPlugin):
    """
    This class is for backward compatibility only and is an
    adapter for using barbican style auth_plugin in place of
    the recommended keystone auth_plugin.
    """
    def __init__(self, barbican_auth_plugin):
        self.barbican_auth_plugin = barbican_auth_plugin

    def get_token(self, session, **kwargs):
        return self.barbican_auth_plugin.auth_token

    def get_endpoint(self, session, **kwargs):
        # NOTE(gyee): this is really a hack as Barbican auth plugin only
        # cares about Barbican endpoint.
        return self.barbican_auth_plugin.barbican_url


def _discover_keystone_info(auth_url):
    # From the auth_url, figure the keystone client version to use
    try:
        disco = discover.Discover(auth_url=auth_url)
        versions = disco.available_versions()
    except:
        error_msg = 'Error: failed to discover keystone version '\
                    'using auth_url: %s' % auth_url
        raise ValueError(error_msg)
    else:
        # use the first one in the list
        if len(versions) > 0:
            version = versions[0]['id']
        else:
            error_msg = 'Error: Unable to discover a keystone plugin '\
                        'for the specified --os-auth-url.\n'\
                        'Please provide a valid auth url'
            raise ValueError(error_msg)
    try:
        # the input auth_url may not have the version info in the
        # url. get the correct auth_url from the versions
        auth_url = versions[0]['links'][0]['href']
    except:
        raise ValueError('Error: Unable to discover the correct auth url')
    return version, auth_url


def create_keystone_auth_session(args):
    """
    Creates an authenticated keystone session using
    the supplied arguments.
    """
    version, auth_url = _discover_keystone_info(args.os_auth_url)
    project_name = args.os_project_name or args.os_tenant_name
    project_id = args.os_project_id or args.os_tenant_id

    # FIXME(tsv): we are depending on the keystone version interface here.
    # If keystone changes it, this code will need to be changed accordingly
    if version == 'v2.0':
        # create a V2 Password plugin
        from keystoneclient.auth.identity import v2
        auth_plugin = v2.Password(auth_url=auth_url,
                                  username=args.os_username,
                                  password=args.os_password,
                                  tenant_name=project_name,
                                  tenant_id=project_id)
    elif version == 'v3.0':
        # create a V3 Password plugin
        from keystoneclient.auth.identity import v3
        auth_plugin = v3.Password(auth_url=auth_url,
                                  username=args.os_username,
                                  user_id=args.os_user_id,
                                  user_domain_name=args.os_user_domain_name,
                                  user_domain_id=args.os_user_domain_id,
                                  password=args.os_password,
                                  project_id=project_id,
                                  project_name=project_name,
                                  project_domain_id=args.os_project_domain_id,
                                  project_domain_name=args.
                                  os_project_domain_name)
    else:
        raise ValueError('Error: unsupported keystone version!')
    return ks_session.Session(auth=auth_plugin, verify=not args.insecure)


class AuthException(Exception):

    """Raised when authorization fails."""
    pass


@six.add_metaclass(abc.ABCMeta)
class AuthPluginBase(object):

    """Base class for Auth plugins."""

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
        if not keystone:
            tenant_info = tenant_name or tenant_id
            if not all([auth_url, username, password, tenant_info]):
                raise ValueError('Please provide auth_url, username, password,'
                                 ' and tenant_id or tenant_name.')

        self._barbican_url = None
        # TODO(dmend): make these configurable
        self._service_type = 'keystore'
        self._endpoint_type = 'publicURL'

        self._keystone = keystone or ksclient.Client(username=username,
                                                     password=password,
                                                     tenant_name=tenant_name,
                                                     tenant_id=tenant_id,
                                                     auth_url=auth_url,
                                                     insecure=insecure)
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
            # TODO(dmend): get barbican_url from catalog
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
