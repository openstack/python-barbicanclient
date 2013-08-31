
from exceptions import ClientException

from keystoneclient.v2_0 import client as ksclient
from keystoneclient import exceptions


def authenticate(auth_url, user, key, tenant, **kwargs):
    #TODO(dmend): remove this method
    keystone = KeystoneAuth(auth_url=auth_url,
                            username=user,
                            password=key,
                            tenant_name=tenant)
    return keystone.barbican_url, keysotone.auth_token


class AuthException(Exception):
    """Raised when authorization fails."""
    def __init__(self, message):
        self.message = message


class KeystoneAuth(object):
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
