# Copyright (c) 2014 Rackspace, Inc.
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
import functools
import logging

from oslo_utils.timeutils import parse_isotime

from barbicanclient import base
from barbicanclient import formatter
from barbicanclient.v1 import acls as acl_manager
from barbicanclient.v1 import secrets as secret_manager


LOG = logging.getLogger(__name__)


def _immutable_after_save(func):
    @functools.wraps(func)
    def wrapper(self, *args):
        if hasattr(self, '_container_ref') and self._container_ref:
            raise base.ImmutableException()
        return func(self, *args)
    return wrapper


class ContainerFormatter(formatter.EntityFormatter):

    columns = ("Container href",
               "Name",
               "Created",
               "Status",
               "Type",
               "Secrets",
               "Consumers",
               )

    def _get_formatted_data(self):
        formatted_secrets = None
        formatted_consumers = None
        if self.secrets:
            formatted_secrets = '\n'.join((
                '='.join((name, secret_ref)) if name else secret_ref
                for name, secret_ref in self.secret_refs.items()
            ))
        if self.consumers:
            formatted_consumers = '\n'.join((str(c) for c in self.consumers))
        created = self.created.isoformat() if self.created else None
        data = (self.container_ref,
                self.name,
                created,
                self.status,
                self._type,
                formatted_secrets,
                formatted_consumers,
                )
        return data


class Container(ContainerFormatter):
    """Container is a generic grouping of Secrets"""
    _entity = 'containers'
    _type = 'generic'

    def __init__(self, api, name=None, secrets=None, consumers=None,
                 container_ref=None, created=None, updated=None, status=None,
                 secret_refs=None):
        self._api = api
        self._secret_manager = secret_manager.SecretManager(api)
        self._name = name
        self._container_ref = container_ref
        self._secret_refs = secret_refs
        self._cached_secrets = dict()
        self._initialize_secrets(secrets)
        if container_ref:
            self._consumers = consumers if consumers else list()
            self._created = parse_isotime(created) if created else None
            self._updated = parse_isotime(updated) if updated else None
            self._status = status
        else:
            self._consumers = list()
            self._created = None
            self._updated = None
            self._status = None
        self._acl_manager = acl_manager.ACLManager(api)
        self._acls = None

    def _initialize_secrets(self, secrets):
        try:
            self._fill_secrets_from_secret_refs()
        except Exception:
            raise ValueError("One or more of the provided secret_refs could "
                             "not be retrieved!")
        if secrets:
            try:
                for name, secret in secrets.items():
                    self.add(name, secret)
            except Exception:
                raise ValueError("One or more of the provided secrets are not "
                                 "valid Secret objects!")

    def _fill_secrets_from_secret_refs(self):
        if self._secret_refs:
            self._cached_secrets = dict(
                (name.lower() if name else "",
                 self._secret_manager.get(secret_ref=secret_ref))
                for name, secret_ref in self._secret_refs.items()
            )

    @property
    def container_ref(self):
        return self._container_ref

    @property
    def name(self):
        if self._container_ref and not self._name:
            self._reload()
        return self._name

    @property
    def created(self):
        return self._created

    @property
    def updated(self):
        return self._updated

    @property
    def status(self):
        if self._container_ref and not self._status:
            self._reload()
        return self._status

    @property
    def acls(self):
        """Get ACL settings for this container."""
        if self._container_ref and not self._acls:
            self._acls = self._acl_manager.get(self.container_ref)
        return self._acls

    @property
    def secret_refs(self):
        if self._cached_secrets:
            self._secret_refs = dict(
                (name, secret.secret_ref)
                for name, secret in self._cached_secrets.items()
            )

        return self._secret_refs

    @property
    def secrets(self, cache=True):
        """List of Secrets in Containers"""
        if not self._cached_secrets or not cache:
            self._fill_secrets_from_secret_refs()
        return self._cached_secrets

    @property
    def consumers(self):
        return self._consumers

    @name.setter
    @_immutable_after_save
    def name(self, value):
        self._name = value

    @_immutable_after_save
    def add(self, name, secret):
        if not isinstance(secret, secret_manager.Secret):
            raise ValueError("Must provide a valid Secret object")
        if name.lower() in self.secrets:
            raise KeyError("A secret with this name already exists!")
        self._cached_secrets[name.lower()] = secret

    @_immutable_after_save
    def remove(self, name):
        self._cached_secrets.pop(name.lower(), None)
        if self._secret_refs:
            self._secret_refs.pop(name.lower(), None)

    @_immutable_after_save
    def store(self):
        """Store Container in Barbican"""
        secret_refs = self._get_secrets_and_store_them_if_necessary()

        container_dict = base.filter_null_keys({
            'name': self.name,
            'type': self._type,
            'secret_refs': secret_refs
        })

        LOG.debug("Request body: {0}".format(container_dict))

        # Save, store container_ref and return
        response = self._api.post(self._entity, json=container_dict)
        if response:
            self._container_ref = response['container_ref']
        return self.container_ref

    def delete(self):
        """Delete container from Barbican"""
        if self._container_ref:
            uuid_ref = base.calculate_uuid_ref(self._container_ref,
                                               self._entity)
            self._api.delete(uuid_ref)
            self._container_ref = None
            self._status = None
            self._created = None
            self._updated = None
        else:
            raise LookupError("Secret is not yet stored.")

    def _get_secrets_and_store_them_if_necessary(self):
        # Save all secrets if they are not yet saved
        LOG.debug("Storing secrets: {0}".format(base.censored_copy(
                                                self.secrets, ['payload'])))
        secret_refs = []
        for name, secret in self.secrets.items():
            if secret and not secret.secret_ref:
                secret.store()
            secret_refs.append({'name': name, 'secret_ref': secret.secret_ref})
        return secret_refs

    def _reload(self):
        if not self._container_ref:
            raise AttributeError("container_ref not set, cannot reload data.")
        LOG.debug('Getting container - Container href: {0}'
                  .format(self._container_ref))
        uuid_ref = base.calculate_uuid_ref(self._container_ref,
                                           self._entity)
        try:
            response = self._api.get(uuid_ref)
        except AttributeError:
            raise LookupError('Container {0} could not be found.'
                              .format(self._container_ref))
        self._name = response.get('name')
        self._consumers = response.get('consumers', [])
        created = response.get('created')
        updated = response.get('updated')
        self._created = parse_isotime(created) if created else None
        self._updated = parse_isotime(updated) if updated else None
        self._status = response.get('status')

    def _get_named_secret(self, name):
        return self.secrets.get(name)

    def __repr__(self):
        return 'Container(name="{0}")'.format(self.name)


class RSAContainerFormatter(formatter.EntityFormatter):
    _get_generic_data = ContainerFormatter._get_formatted_data

    def _get_generic_columns(self):
        return ContainerFormatter.columns

    columns = ("Container href",
               "Name",
               "Created",
               "Status",
               "Type",
               "Public Key",
               "Private Key",
               "PK Passphrase",
               "Consumers",
               )

    def _get_formatted_data(self):
        formatted_public_key = None
        formatted_private_key = None
        formatted_pkp = None
        formatted_consumers = None
        if self.public_key:
            formatted_public_key = self.public_key.secret_ref
        if self.private_key:
            formatted_private_key = self.private_key.secret_ref
        if self.private_key_passphrase:
            formatted_pkp = self.private_key_passphrase.secret_ref
        if self.consumers:
            formatted_consumers = '\n'.join((str(c) for c in self.consumers))
        data = (self.container_ref,
                self.name,
                self.created,
                self.status,
                self._type,
                formatted_public_key,
                formatted_private_key,
                formatted_pkp,
                formatted_consumers,
                )
        return data


class RSAContainer(RSAContainerFormatter, Container):
    _required_secrets = ["public_key", "private_key"]
    _optional_secrets = ["private_key_passphrase"]
    _type = 'rsa'

    def __init__(self, api, name=None, public_key=None, private_key=None,
                 private_key_passphrase=None, consumers=[], container_ref=None,
                 created=None, updated=None, status=None, public_key_ref=None,
                 private_key_ref=None, private_key_passphrase_ref=None):
        secret_refs = {}
        if public_key_ref:
            secret_refs['public_key'] = public_key_ref
        if private_key_ref:
            secret_refs['private_key'] = private_key_ref
        if private_key_passphrase_ref:
            secret_refs['private_key_passphrase'] = private_key_passphrase_ref
        super(RSAContainer, self).__init__(
            api=api,
            name=name,
            consumers=consumers,
            container_ref=container_ref,
            created=created,
            updated=updated,
            status=status,
            secret_refs=secret_refs
        )
        if public_key:
            self.public_key = public_key
        if private_key:
            self.private_key = private_key
        if private_key_passphrase:
            self.private_key_passphrase = private_key_passphrase

    @property
    def public_key(self):
        """Secret containing the Public Key"""
        return self._get_named_secret("public_key")

    @property
    def private_key(self):
        """Secret containing the Private Key"""
        return self._get_named_secret("private_key")

    @property
    def private_key_passphrase(self):
        """Secret containing the Passphrase"""
        return self._get_named_secret("private_key_passphrase")

    @public_key.setter
    @_immutable_after_save
    def public_key(self, value):
        super(RSAContainer, self).remove("public_key")
        super(RSAContainer, self).add("public_key", value)

    @private_key.setter
    @_immutable_after_save
    def private_key(self, value):
        super(RSAContainer, self).remove("private_key")
        super(RSAContainer, self).add("private_key", value)

    @private_key_passphrase.setter
    @_immutable_after_save
    def private_key_passphrase(self, value):
        super(RSAContainer, self).remove("private_key_passphrase")
        super(RSAContainer, self).add("private_key_passphrase", value)

    def add(self, name, sec):
        raise NotImplementedError("`add()` is not implemented for "
                                  "Typed Containers")

    def __repr__(self):
        return 'RSAContainer(name="{0}")'.format(self.name)


class CertificateContainerFormatter(formatter.EntityFormatter):
    _get_generic_data = ContainerFormatter._get_formatted_data

    def _get_generic_columns(self):
        return ContainerFormatter.columns

    columns = ("Container href",
               "Name",
               "Created",
               "Status",
               "Type",
               "Certificate",
               "Intermediates",
               "Private Key",
               "PK Passphrase",
               "Consumers",
               )

    def _get_formatted_data(self):
        formatted_certificate = None
        formatted_private_key = None
        formatted_pkp = None
        formatted_intermediates = None
        formatted_consumers = None
        if self.certificate:
            formatted_certificate = self.certificate.secret_ref
        if self.intermediates:
            formatted_intermediates = self.intermediates.secret_ref
        if self.private_key:
            formatted_private_key = self.private_key.secret_ref
        if self.private_key_passphrase:
            formatted_pkp = self.private_key_passphrase.secret_ref
        if self.consumers:
            formatted_consumers = '\n'.join((str(c) for c in self.consumers))
        data = (self.container_ref,
                self.name,
                self.created,
                self.status,
                self._type,
                formatted_certificate,
                formatted_intermediates,
                formatted_private_key,
                formatted_pkp,
                formatted_consumers,
                )
        return data


class CertificateContainer(CertificateContainerFormatter, Container):
    _required_secrets = ["certificate", "private_key"]
    _optional_secrets = ["private_key_passphrase", "intermediates"]
    _type = 'certificate'

    def __init__(self, api, name=None, certificate=None, intermediates=None,
                 private_key=None, private_key_passphrase=None, consumers=[],
                 container_ref=None, created=None, updated=None, status=None,
                 certificate_ref=None, intermediates_ref=None,
                 private_key_ref=None, private_key_passphrase_ref=None):
        secret_refs = {}
        if certificate_ref:
            secret_refs['certificate'] = certificate_ref
        if intermediates_ref:
            secret_refs['intermediates'] = intermediates_ref
        if private_key_ref:
            secret_refs['private_key'] = private_key_ref
        if private_key_passphrase_ref:
            secret_refs['private_key_passphrase'] = private_key_passphrase_ref
        super(CertificateContainer, self).__init__(
            api=api,
            name=name,
            consumers=consumers,
            container_ref=container_ref,
            created=created,
            updated=updated,
            status=status,
            secret_refs=secret_refs
        )
        if certificate:
            self.certificate = certificate
        if intermediates:
            self.intermediates = intermediates
        if private_key:
            self.private_key = private_key
        if private_key_passphrase:
            self.private_key_passphrase = private_key_passphrase

    @property
    def certificate(self):
        """Secret containing the certificate"""
        return self._get_named_secret("certificate")

    @property
    def private_key(self):
        """Secret containing the private key"""
        return self._get_named_secret("private_key")

    @property
    def private_key_passphrase(self):
        """Secret containing the passphrase"""
        return self._get_named_secret("private_key_passphrase")

    @property
    def intermediates(self):
        """Secret containing intermediate certificates"""
        return self._get_named_secret("intermediates")

    @certificate.setter
    @_immutable_after_save
    def certificate(self, value):
        super(CertificateContainer, self).remove("certificate")
        super(CertificateContainer, self).add("certificate", value)

    @private_key.setter
    @_immutable_after_save
    def private_key(self, value):
        super(CertificateContainer, self).remove("private_key")
        super(CertificateContainer, self).add("private_key", value)

    @private_key_passphrase.setter
    @_immutable_after_save
    def private_key_passphrase(self, value):
        super(CertificateContainer, self).remove("private_key_passphrase")
        super(CertificateContainer, self).add("private_key_passphrase", value)

    @intermediates.setter
    @_immutable_after_save
    def intermediates(self, value):
        super(CertificateContainer, self).remove("intermediates")
        super(CertificateContainer, self).add("intermediates", value)

    def add(self, name, sec):
        raise NotImplementedError("`add()` is not implemented for "
                                  "Typed Containers")

    def __repr__(self):
        return 'CertificateContainer(name="{0}")'.format(self.name)


class ContainerManager(base.BaseEntityManager):
    """EntityManager for Container entities

    You should use the ContainerManager exposed by the Client and should not
    need to instantiate your own.
    """

    _container_map = {
        'generic': Container,
        'rsa': RSAContainer,
        'certificate': CertificateContainer
    }

    def __init__(self, api):
        super(ContainerManager, self).__init__(api, 'containers')

    def get(self, container_ref):
        """Retrieve an existing Container from Barbican

        :param container_ref: Full HATEOAS reference to a Container, or a UUID
        :returns: Container object or a subclass of the appropriate type
        """
        LOG.debug('Getting container - Container href: {0}'
                  .format(container_ref))
        uuid_ref = base.calculate_uuid_ref(container_ref, self._entity)
        try:
            response = self._api.get(uuid_ref)
        except AttributeError:
            raise LookupError('Container {0} could not be found.'
                              .format(container_ref))
        return self._generate_typed_container(response)

    def _generate_typed_container(self, response):
        resp_type = response.get('type', '').lower()
        container_type = self._container_map.get(resp_type)
        if not container_type:
            raise TypeError('Unknown container type "{0}".'
                            .format(resp_type))

        name = response.get('name')
        consumers = response.get('consumers', [])
        container_ref = response.get('container_ref')
        created = response.get('created')
        updated = response.get('updated')
        status = response.get('status')
        secret_refs = self._translate_secret_refs_from_json(
            response.get('secret_refs')
        )

        if container_type is RSAContainer:
            public_key_ref = secret_refs.get('public_key')
            private_key_ref = secret_refs.get('private_key')
            private_key_pass_ref = secret_refs.get('private_key_passphrase')
            return RSAContainer(
                api=self._api,
                name=name,
                consumers=consumers,
                container_ref=container_ref,
                created=created,
                updated=updated,
                status=status,
                public_key_ref=public_key_ref,
                private_key_ref=private_key_ref,
                private_key_passphrase_ref=private_key_pass_ref,
            )
        elif container_type is CertificateContainer:
            certificate_ref = secret_refs.get('certificate')
            intermediates_ref = secret_refs.get('intermediates')
            private_key_ref = secret_refs.get('private_key')
            private_key_pass_ref = secret_refs.get('private_key_passphrase')
            return CertificateContainer(
                api=self._api,
                name=name,
                consumers=consumers,
                container_ref=container_ref,
                created=created,
                updated=updated,
                status=status,
                certificate_ref=certificate_ref,
                intermediates_ref=intermediates_ref,
                private_key_ref=private_key_ref,
                private_key_passphrase_ref=private_key_pass_ref,
            )
        return container_type(
            api=self._api,
            name=name,
            secret_refs=secret_refs,
            consumers=consumers,
            container_ref=container_ref,
            created=created,
            updated=updated,
            status=status
        )

    @staticmethod
    def _translate_secret_refs_from_json(json_refs):
        return dict(
            (ref_pack.get('name'), ref_pack.get('secret_ref'))
            for ref_pack in json_refs
        )

    def create(self, name=None, secrets=None):
        """Factory method for `Container` objects

        `Container` objects returned by this method have not yet been
        stored in Barbican.

        :param name: A friendly name for the Container
        :param secrets: Secrets to populate when creating a Container
        :returns: Container
        :rtype: :class:`barbicanclient.v1.containers.Container`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        return Container(
            api=self._api,
            name=name,
            secrets=secrets
        )

    def create_rsa(self, name=None, public_key=None, private_key=None,
                   private_key_passphrase=None):
        """Factory method for `RSAContainer` objects

        `RSAContainer` objects returned by this method have not yet been
        stored in Barbican.

        :param name: A friendly name for the RSAContainer
        :param public_key: Secret object containing a Public Key
        :param private_key: Secret object containing a Private Key
        :param private_key_passphrase: Secret object containing a passphrase
        :returns: RSAContainer
        :rtype: :class:`barbicanclient.v1.containers.RSAContainer`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        return RSAContainer(
            api=self._api,
            name=name,
            public_key=public_key,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase
        )

    def create_certificate(self, name=None, certificate=None,
                           intermediates=None, private_key=None,
                           private_key_passphrase=None):
        """Factory method for `CertificateContainer` objects

        `CertificateContainer` objects returned by this method have not yet
        been stored in Barbican.

        :param name: A friendly name for the CertificateContainer
        :param certificate: Secret object containing a Certificate
        :param intermediates: Secret object containing Intermediate Certs
        :param private_key: Secret object containing a Private Key
        :param private_key_passphrase: Secret object containing a passphrase
        :returns: CertificateContainer
        :rtype: :class:`barbicanclient.v1.containers.CertificateContainer`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        return CertificateContainer(
            api=self._api,
            name=name,
            certificate=certificate,
            intermediates=intermediates,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase
        )

    def delete(self, container_ref):
        """Delete a Container from Barbican

        :param container_ref: Full HATEOAS reference to a Container, or a UUID
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        if not container_ref:
            raise ValueError('container_ref is required.')
        uuid_ref = base.calculate_uuid_ref(container_ref, self._entity)
        self._api.delete(uuid_ref)

    def list(self, limit=10, offset=0, name=None, type=None):
        """List containers for the project.

        This method uses the limit and offset
        parameters for paging.

        :param limit: Max number of containers returned
        :param offset: Offset containers to begin list
        :param name: Name filter for the list
        :param type: Type filter for the list
        :returns: list of Container metadata objects
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Listing containers - offset {0} limit {1} name {2} type {3}'
                  .format(offset, limit, name, type))
        params = {'limit': limit, 'offset': offset}
        if name:
            params['name'] = name
        if type:
            params['type'] = type

        response = self._api.get(self._entity, params=params)

        return [self._generate_typed_container(container)
                for container in response.get('containers', [])]

    def register_consumer(self, container_ref, name, url):
        """Add a consumer to the container

        :param container_ref: Full HATEOAS reference to a Container, or a UUID
        :param name: Name of the consuming service
        :param url: URL of the consuming resource
        :returns: A container object per the get() method
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Creating consumer registration for container '
                  '{0} as {1}: {2}'.format(container_ref, name, url))
        container_uuid = base.validate_ref_and_return_uuid(
            container_ref, 'Container')
        href = '{0}/{1}/consumers'.format(self._entity, container_uuid)
        consumer_dict = dict()
        consumer_dict['name'] = name
        consumer_dict['URL'] = url

        response = self._api.post(href, json=consumer_dict)
        return self._generate_typed_container(response)

    def remove_consumer(self, container_ref, name, url):
        """Remove a consumer from the container

        :param container_ref: Full HATEOAS reference to a Container, or a UUID
        :param name: Name of the previously consuming service
        :param url: URL of the previously consuming resource
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Deleting consumer registration for container '
                  '{0} as {1}: {2}'.format(container_ref, name, url))
        container_uuid = base.validate_ref_and_return_uuid(
            container_ref, 'Container')
        href = '{0}/{1}/consumers'.format(self._entity, container_uuid)
        consumer_dict = {
            'name': name,
            'URL': url
        }

        self._api.delete(href, json=consumer_dict)
