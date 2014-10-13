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
import mock
from oslo.utils import timeutils

from barbicanclient.test import test_client
from barbicanclient import base, containers, secrets


class ContainerData(object):
    def __init__(self):
        self.name = 'Self destruction sequence'
        self.type = 'generic'
        self.secret = mock.Mock(spec=secrets.Secret)
        self.secret.__bases__ = (secrets.Secret,)
        self.secret.secret_ref = 'http://a/b/1'
        self.secret.name = 'thing1'
        self.generic_secret_refs = {self.secret.name: self.secret.secret_ref}
        self.generic_secret_refs_json = [{'name': self.secret.name,
                                         'secret_ref': self.secret.secret_ref}]
        self.generic_secrets = {self.secret.name: self.secret}
        self.rsa_secret_refs = {
            'private_key': self.secret.secret_ref,
            'public_key': self.secret.secret_ref,
            'private_key_passphrase': self.secret.secret_ref,
        }
        self.rsa_secret_refs_json = [
            {'name': 'private_key',
             'secret_ref': self.secret.secret_ref},
            {'name': 'public_key',
             'secret_ref': self.secret.secret_ref},
            {'name': 'private_key_passphrase',
             'secret_ref': self.secret.secret_ref},
        ]
        self.certificate_secret_refs = {
            'certificate': self.secret.secret_ref,
            'private_key': self.secret.secret_ref,
            'private_key_passphrase': self.secret.secret_ref,
            'intermediates': self.secret.secret_ref,
        }
        self.certificate_secret_refs_json = [
            {'name': 'certificate',
             'secret_ref': self.secret.secret_ref},
            {'name': 'private_key',
             'secret_ref': self.secret.secret_ref},
            {'name': 'private_key_passphrase',
             'secret_ref': self.secret.secret_ref},
            {'name': 'intermediates',
             'secret_ref': self.secret.secret_ref},
        ]
        self.created = str(timeutils.utcnow())
        self.consumer = {'name': 'testing', 'URL': 'http://c.d/e'}

        self.container_dict = {'name': self.name,
                               'status': 'ACTIVE',
                               'created': self.created}

    def get_dict(self, container_ref=None, type='generic', consumers=None):
        container = self.container_dict
        if container_ref:
            container['container_ref'] = container_ref
        container['type'] = type
        if type == 'rsa':
            container['secret_refs'] = self.rsa_secret_refs_json
        elif type == 'certificate':
            container['secret_refs'] = self.certificate_secret_refs_json
        else:
            container['secret_refs'] = self.generic_secret_refs_json
        if consumers:
            container['consumers'] = consumers
        return container


class WhenTestingContainers(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('containers')

        self.container = ContainerData()
        self.api.secrets.Secret.return_value = self.container.secret
        self.manager = containers.ContainerManager(self.api)
        self.consumers_post_resource = (
            self.entity_href.replace(self.endpoint + '/', '') + '/consumers'
        )
        self.consumers_delete_resource = (
            self.entity_href + '/consumers'
        )

    def test_should_generic_container_str(self):
        container_obj = self.manager.create(name=self.container.name)
        self.assertIn(self.container.name, str(container_obj))
        self.assertIn(' generic ', str(container_obj))

    def test_should_certificate_container_str(self):
        container_obj = self.manager.create_certificate(
            name=self.container.name)
        self.assertIn(self.container.name, str(container_obj))
        self.assertIn(' certificate ', str(container_obj))

    def test_should_rsa_container_str(self):
        container_obj = self.manager.create_rsa(name=self.container.name)
        self.assertIn(self.container.name, str(container_obj))
        self.assertIn(' rsa ', str(container_obj))

    def test_should_generic_container_repr(self):
        container_obj = self.manager.create(name=self.container.name)
        self.assertIn('name="{0}"'.format(self.container.name),
                      repr(container_obj))

    def test_should_certificate_container_repr(self):
        container_obj = self.manager.create_certificate(
            name=self.container.name)
        self.assertIn('name="{0}"'.format(self.container.name),
                      repr(container_obj))

    def test_should_rsa_container_repr(self):
        container_obj = self.manager.create_rsa(name=self.container.name)
        self.assertIn('name="{0}"'.format(self.container.name),
                      repr(container_obj))

    def test_should_store_generic_via_constructor(self):
        self.api._post.return_value = {'container_ref': self.entity_href}

        container = self.manager.create(
            name=self.container.name,
            secrets=self.container.generic_secrets
        )
        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        container_req = args[1]
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual(self.container.type, container_req['type'])
        self.assertEqual(self.container.generic_secret_refs_json,
                         container_req['secret_refs'])

    def test_should_store_generic_via_attributes(self):
        self.api._post.return_value = {'container_ref': self.entity_href}

        container = self.manager.create()
        container.name = self.container.name
        container.add(self.container.secret.name, self.container.secret)

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        container_req = args[1]
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual(self.container.type, container_req['type'])
        self.assertItemsEqual(self.container.generic_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_store_certificate_via_attributes(self):
        self.api._post.return_value = {'container_ref': self.entity_href}

        container = self.manager.create_certificate()
        container.name = self.container.name
        container.certificate = self.container.secret
        container.private_key = self.container.secret
        container.private_key_passphrase = self.container.secret
        container.intermediates = self.container.secret

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        container_req = args[1]
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual('certificate', container_req['type'])
        self.assertItemsEqual(self.container.certificate_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_store_certificate_via_constructor(self):
        self.api._post.return_value = {'container_ref': self.entity_href}

        container = self.manager.create_certificate(
            name=self.container.name,
            certificate=self.container.secret,
            private_key=self.container.secret,
            private_key_passphrase=self.container.secret,
            intermediates=self.container.secret
        )
        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        container_req = args[1]
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual('certificate', container_req['type'])
        self.assertItemsEqual(self.container.certificate_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_store_rsa_via_attributes(self):
        self.api._post.return_value = {'container_ref': self.entity_href}

        container = self.manager.create_rsa()
        container.name = self.container.name
        container.private_key = self.container.secret
        container.private_key_passphrase = self.container.secret
        container.public_key = self.container.secret

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        container_req = args[1]
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual('rsa', container_req['type'])
        self.assertItemsEqual(self.container.rsa_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_store_rsa_via_constructor(self):
        self.api._post.return_value = {'container_ref': self.entity_href}

        container = self.manager.create_rsa(
            name=self.container.name,
            private_key=self.container.secret,
            private_key_passphrase=self.container.secret,
            public_key=self.container.secret
        )

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        container_req = args[1]
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual('rsa', container_req['type'])
        self.assertItemsEqual(self.container.rsa_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_get_secret_refs_when_created_using_secret_objects(self):
        self.api._post.return_value = {'container_ref': self.entity_href}

        container = self.manager.create(
            name=self.container.name,
            secrets=self.container.generic_secrets
        )

        self.assertEqual(container.secret_refs,
                         self.container.generic_secret_refs)

    def test_should_reload_attributes_after_store(self):
        self.api._post.return_value = {'container_ref': self.entity_href}
        self.api._get.return_value = self.container.get_dict(self.entity_href)

        container = self.manager.create(
            name=self.container.name,
            secrets=self.container.generic_secrets
        )

        self.assertIsNone(container.status)
        self.assertIsNone(container.created)
        self.assertIsNone(container.updated)

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        self.assertIsNotNone(container.status)
        self.assertIsNotNone(container.created)

    def test_should_fail_add_invalid_secret_object(self):
        container = self.manager.create()
        self.assertRaises(ValueError, container.add, "Not-a-secret",
                          "Actually a string")

    def test_should_fail_add_duplicate_named_secret_object(self):
        container = self.manager.create()
        container.add(self.container.secret.name, self.container.secret)
        self.assertRaises(KeyError, container.add, self.container.secret.name,
                          self.container.secret)

    def test_should_add_remove_add_secret_object(self):
        container = self.manager.create()
        container.add(self.container.secret.name, self.container.secret)
        container.remove(self.container.secret.name)
        container.add(self.container.secret.name, self.container.secret)

    def test_should_be_immutable_after_store(self):
        self.api._post.return_value = {'container_ref': self.entity_href}

        container = self.manager.create(
            name=self.container.name,
            secrets=self.container.generic_secrets
        )
        container_href = container.store()

        self.assertEqual(self.entity_href, container_href)

        # Verify that attributes are immutable after store.
        attributes = [
            "name"
        ]
        for attr in attributes:
            try:
                setattr(container, attr, "test")
                self.fail("didn't raise an ImmutableException exception")
            except base.ImmutableException:
                pass
        self.assertRaises(base.ImmutableException, container.add,
                          self.container.secret.name, self.container.secret)

    def test_should_not_be_able_to_set_generated_attributes(self):
        container = self.manager.create()

        # Verify that generated attributes cannot be set.
        attributes = [
            "container_ref", "created", "updated", "status", "consumers"
        ]
        for attr in attributes:
            try:
                setattr(container, attr, "test")
                self.fail("didn't raise an AttributeError exception")
            except AttributeError:
                pass

    def test_should_get_generic_container(self):
        self.api._get.return_value = self.container.get_dict(self.entity_href)

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsInstance(container, containers.Container)
        self.assertEqual(self.entity_href, container.container_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)
        self.assertIsNotNone(container.secrets)

    def test_should_get_certificate_container(self):
        self.api._get.return_value = self.container.get_dict(
            self.entity_href, type='certificate'
        )

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsInstance(container, containers.Container)
        self.assertEqual(self.entity_href, container.container_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify the returned type is correct
        self.assertIsInstance(container, containers.CertificateContainer)
        self.assertIsNotNone(container.certificate)
        self.assertIsNotNone(container.private_key)
        self.assertIsNotNone(container.private_key_passphrase)
        self.assertIsNotNone(container.intermediates)

    def test_should_get_rsa_container(self):
        self.api._get.return_value = self.container.get_dict(self.entity_href,
                                                             type='rsa')

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsInstance(container, containers.Container)
        self.assertEqual(self.entity_href, container.container_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify the returned type is correct
        self.assertIsInstance(container, containers.RSAContainer)
        self.assertIsNotNone(container.private_key)
        self.assertIsNotNone(container.public_key)
        self.assertIsNotNone(container.private_key_passphrase)

    def test_should_delete_from_manager(self):
        self.manager.delete(container_ref=self.entity_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._delete.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_delete_from_object(self):
        self.api._get.return_value = self.container.get_dict(self.entity_href)

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsNotNone(container.container_ref)

        container.delete()

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._delete.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify that the Container no longer has a container_ref
        self.assertIsNone(container.container_ref)

    def test_should_store_after_delete_from_object(self):
        self.api._get.return_value = self.container.get_dict(self.entity_href)

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsNotNone(container.container_ref)

        container.delete()

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._delete.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify that the Container no longer has a container_ref
        self.assertIsNone(container.container_ref)

        container.store()

        # Verify that the Container has a container_ref again
        self.assertIsNotNone(container.container_ref)

    def test_should_get_list(self):
        container_resp = self.container.get_dict(self.entity_href)
        self.api._get.return_value = {"containers":
                                      [container_resp for v in range(3)]}

        containers_list = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(containers_list) == 3)
        self.assertIsInstance(containers_list[0], containers.Container)
        self.assertEqual(self.entity_href, containers_list[0].container_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api._get.call_args
        url = args[0]
        self.assertEqual(self.entity_base[:-1], url)

        # Verify that correct information was sent in the call.
        params = args[1]
        self.assertEqual(10, params['limit'])
        self.assertEqual(5, params['offset'])

    def test_should_fail_get_invalid_container(self):
        self.assertRaises(ValueError, self.manager.get,
                          **{'container_ref': '12345'})

    def test_should_fail_delete_no_href(self):
        self.assertRaises(ValueError, self.manager.delete, None)

    def test_should_register_consumer(self):
        self.api._post.return_value = self.container.get_dict(
            self.entity_href, consumers=[self.container.consumer]
        )
        container = self.manager.register_consumer(
            self.entity_href, self.container.consumer.get('name'),
            self.container.consumer.get('URL')
        )
        self.assertIsInstance(container, containers.Container)
        self.assertEqual(self.entity_href, container.container_ref)

        args, kwargs = self.api._post.call_args
        url, body = args[0], args[1]

        self.assertEqual(self.consumers_post_resource, url)
        self.assertEqual(self.container.consumer, body)
        self.assertEqual([self.container.consumer], container.consumers)

    def test_should_remove_consumer(self):
        self.manager.remove_consumer(
            self.entity_href, self.container.consumer.get('name'),
            self.container.consumer.get('URL')
        )

        args, kwargs = self.api._delete.call_args
        url = args[0]
        body = kwargs['json']

        self.assertEqual(self.consumers_delete_resource, url)
        self.assertEqual(self.container.consumer, body)

    def test_should_get_total(self):
        self.api._get.return_value = {'total': 1}
        total = self.manager.total()
        self.assertEqual(total, 1)
