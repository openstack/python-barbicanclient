
from exceptions import ClientException

from keystoneclient.v2_0 import client as ksclient
from keystoneclient import exceptions


def authenticate(auth_url, user, key, tenant, **kwargs):
    """Authenticates against the endpoint to use. The correct
    endpoint to use is looked up in the service catalog. The
    caller can override this lookup by passing the endpoint
    as a parameter.

    :param auth_url: The keystone auth endpoint to use
    :param user: The username to use for auth
    :param key: The apikey to use for authentiation
    :param endpoint: The Barbican endpoint to use. IOW, don't
        look up an endpoint in the service catalog, just use
        this one instead.
    :param tenant_name: The optional tenant-name to use
    :param tenant_id: The optional tenant ID toi use
    :param cacert: The cacert PEM file to use
    :param service_type: The service type to look for in
        the service catalog
    :param endpoint_type The endpoint type to reference in
        the service catalog
    :param region_name The region to pass for authentication

    :returns: Tuple containing Barbican endpoint and token

    :raises: ClientException
    """
    insecure = kwargs.get('insecure', False)
    endpoint = kwargs.get('endpoint')
    cacert = kwargs.get('cacert')

    try:
        _ksclient = ksclient.Client(username=user,
                                    password=key,
                                    tenant_name=tenant,
                                    cacert=cacert,
                                    auth_url=auth_url,
                                    insecure=insecure)

    except exceptions.Unauthorized:
        raise ClientException('Unauthorized. Check username, password'
                              ' and tenant name/id')

    except exceptions.AuthorizationFailure:
        raise ClientException('Authorization Failure. %s')

    if not endpoint:
        # The user did not pass in an endpoint, so we need to
        # look one up on their behalf in the service catalog

        # TODO(jdp): Ensure that this is the correct service_type field
        service_type = kwargs.get('service_type', 'queueing')
        endpoint_type = kwargs.get('endpoint_type', 'publicURL')
        region = kwargs.get('region_name')

        try:
            endpoint = _ksclient.service_catalog.url_for(
                attr='region',
                filter_value=region,
                service_type=service_type,
                endpoint_type=endpoint_type)
        except exceptions.EndpointNotFound:
            raise ClientException('Endpoint not found in service catalog')

    return endpoint, _ksclient.auth_token


class AuthException(Exception):
    """Raised when authorization fails."""
    def __init__(self, message):
        self.message = message


class KeystoneAuth(object):
    def __init__(self, endpoint='', username='', password='',
                 tenant_name='', tenant_id=''):
        if not all([endpoint, username, password, tenant_name or tenant_id]):
            raise ValueError('Please provide endpoint, username, password,'
                             ' and tenant_id or tenant_name)')
        self._keystone = ksclient.Client(username=username,
                                         password=password,
                                         tenant_name=tenant_name,
                                         endpoint=endpoint)
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
