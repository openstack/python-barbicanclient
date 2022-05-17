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

from unittest import mock

from oslo_serialization import jsonutils
from oslo_utils import timeutils

from barbicanclient import base
from barbicanclient.tests import test_client
from barbicanclient.v1 import acls
from barbicanclient.v1 import containers
from barbicanclient.v1 import secrets


class ContainerData(object):
    def __init__(self):
        self.name = 'Self destruction sequence'
        self.type = 'generic'
        self.secret = mock.Mock(spec=secrets.Secret)
        self.secret.__bases__ = (secrets.Secret,)
        self.secret.secret_ref = ('http://barbican/v1/secrets/'
                                  'a73b62e4-eee2-4169-9a14-b8bb4da71d87')
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
        self.manager = self.client.containers

        self.consumers_post_resource = self.entity_href + '/consumers/'
        self.consumers_delete_resource = self.entity_href + '/consumers'

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
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        container = self.manager.create(
            name=self.container.name,
            secrets=self.container.generic_secrets
        )
        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base + '/',
                         self.responses.last_request.url)

        # Verify that correct information was sent in the call.
        container_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual(self.container.type, container_req['type'])
        self.assertEqual(self.container.generic_secret_refs_json,
                         container_req['secret_refs'])

    def test_should_store_generic_via_attributes(self):
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        container = self.manager.create()
        container.name = self.container.name
        container.add(self.container.secret.name, self.container.secret)

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base + '/',
                         self.responses.last_request.url)

        # Verify that correct information was sent in the call.
        container_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual(self.container.type, container_req['type'])
        self.assertEqual(self.container.generic_secret_refs_json,
                         container_req['secret_refs'])

    def test_should_store_certificate_via_attributes(self):
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        container = self.manager.create_certificate()
        container.name = self.container.name
        container.certificate = self.container.secret
        container.private_key = self.container.secret
        container.private_key_passphrase = self.container.secret
        container.intermediates = self.container.secret

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base + '/',
                         self.responses.last_request.url)

        # Verify that correct information was sent in the call.
        container_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual('certificate', container_req['type'])
        self.assertCountEqual(self.container.certificate_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_store_certificate_via_constructor(self):
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

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
        self.assertEqual(self.entity_base + '/',
                         self.responses.last_request.url)

        # Verify that correct information was sent in the call.
        container_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual('certificate', container_req['type'])
        self.assertCountEqual(self.container.certificate_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_store_rsa_via_attributes(self):
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        container = self.manager.create_rsa()
        container.name = self.container.name
        container.private_key = self.container.secret
        container.private_key_passphrase = self.container.secret
        container.public_key = self.container.secret

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base + '/',
                         self.responses.last_request.url)

        # Verify that correct information was sent in the call.
        container_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual('rsa', container_req['type'])
        self.assertCountEqual(self.container.rsa_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_store_rsa_via_constructor(self):
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        container = self.manager.create_rsa(
            name=self.container.name,
            private_key=self.container.secret,
            private_key_passphrase=self.container.secret,
            public_key=self.container.secret
        )

        container_href = container.store()
        self.assertEqual(self.entity_href, container_href)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base + '/',
                         self.responses.last_request.url)

        # Verify that correct information was sent in the call.
        container_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.container.name, container_req['name'])
        self.assertEqual('rsa', container_req['type'])
        self.assertCountEqual(self.container.rsa_secret_refs_json,
                              container_req['secret_refs'])

    def test_should_get_secret_refs_when_created_using_secret_objects(self):
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        container = self.manager.create(
            name=self.container.name,
            secrets=self.container.generic_secrets
        )

        self.assertEqual(self.container.generic_secret_refs,
                         container.secret_refs)

    def test_should_reload_attributes_after_store(self):
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        data = self.container.get_dict(self.entity_href)
        self.responses.get(self.entity_href, json=data)

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
        data = {'container_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

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

    def test_should_get_generic_container(self, container_ref=None):
        container_ref = container_ref or self.entity_href

        data = self.container.get_dict(container_ref)
        self.responses.get(self.entity_href, json=data)

        container = self.manager.get(container_ref=container_ref)
        self.assertIsInstance(container, containers.Container)
        self.assertEqual(container_ref, container.container_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)
        self.assertIsNotNone(container.secrets)

    def test_should_get_certificate_container(self):
        data = self.container.get_dict(self.entity_href, type='certificate')
        self.responses.get(self.entity_href, json=data)

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsInstance(container, containers.Container)
        self.assertEqual(self.entity_href, container.container_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

        # Verify the returned type is correct
        self.assertIsInstance(container, containers.CertificateContainer)
        self.assertIsNotNone(container.certificate)
        self.assertIsNotNone(container.private_key)
        self.assertIsNotNone(container.private_key_passphrase)
        self.assertIsNotNone(container.intermediates)

    def test_should_get_rsa_container(self):
        data = self.container.get_dict(self.entity_href, type='rsa')
        self.responses.get(self.entity_href, json=data)

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsInstance(container, containers.Container)
        self.assertEqual(self.entity_href, container.container_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

        # Verify the returned type is correct
        self.assertIsInstance(container, containers.RSAContainer)
        self.assertIsNotNone(container.private_key)
        self.assertIsNotNone(container.public_key)
        self.assertIsNotNone(container.private_key_passphrase)

    def test_should_get_generic_container_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_get_generic_container(bad_href)

    def test_should_get_generic_container_using_only_uuid(self):
        self.test_should_get_generic_container(self.entity_id)

    def test_should_delete_from_manager(self, container_ref=None):
        container_ref = container_ref or self.entity_href

        self.responses.delete(self.entity_href, status_code=204)

        self.manager.delete(container_ref=container_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

    def test_should_delete_from_manager_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_delete_from_manager(bad_href)

    def test_should_delete_from_manager_using_only_uuid(self):
        self.test_should_delete_from_manager(self.entity_id)

    def test_should_delete_from_object(self, container_ref=None):
        container_ref = container_ref or self.entity_href

        data = self.container.get_dict(container_ref)
        m = self.responses.get(self.entity_href, json=data)
        n = self.responses.delete(self.entity_href, status_code=204)

        container = self.manager.get(container_ref=container_ref)
        self.assertEqual(container_ref, container.container_ref)

        container.delete()

        # Verify the correct URL was used to make the call.
        self.assertTrue(m.called)
        self.assertTrue(n.called)

        # Verify that the Container no longer has a container_ref
        self.assertIsNone(container.container_ref)

    def test_should_delete_from_object_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_delete_from_object(bad_href)

    def test_should_delete_from_object_using_only_uuid(self):
        self.test_should_delete_from_object(self.entity_id)

    def test_should_store_after_delete_from_object(self):
        data = self.container.get_dict(self.entity_href)
        self.responses.get(self.entity_href, json=data)

        data = self.container.get_dict(self.entity_href)
        self.responses.post(self.entity_base + '/', json=data)

        m = self.responses.delete(self.entity_href, status_code=204)

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsNotNone(container.container_ref)

        container.delete()

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, m.last_request.url)

        # Verify that the Container no longer has a container_ref
        self.assertIsNone(container.container_ref)

        container.store()

        # Verify that the Container has a container_ref again
        self.assertIsNotNone(container.container_ref)

    def test_should_get_list(self):
        container_resp = self.container.get_dict(self.entity_href)
        data = {"containers": [container_resp for v in range(3)]}
        self.responses.get(self.entity_base, json=data)
        containers_list = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(containers_list) == 3)
        self.assertIsInstance(containers_list[0], containers.Container)
        self.assertEqual(self.entity_href, containers_list[0].container_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base,
                         self.responses.last_request.url.split('?')[0])
        # Verify that correct information was sent in the call.
        self.assertEqual(['10'], self.responses.last_request.qs['limit'])
        self.assertEqual(['5'], self.responses.last_request.qs['offset'])

    def test_should_get_list_when_secret_ref_without_name(self):
        container_resp = self.container.get_dict(self.entity_href)
        del container_resp.get("secret_refs")[0]["name"]
        data = {"containers": [container_resp for v in range(3)]}
        self.responses.get(self.entity_base, json=data)
        containers_list = self.manager.list(limit=10, offset=5)

        self.assertTrue(len(containers_list) == 3)
        self.assertIsInstance(containers_list[0], containers.Container)
        self.assertEqual(self.entity_href, containers_list[0].container_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base,
                         self.responses.last_request.url.split('?')[0])

        # Verify that the names of the secret_refs in the containers are None
        for container in containers_list:
            for name in container._secret_refs.keys():
                self.assertIsNone(name)

    def test_should_fail_get_invalid_container(self):
        self.assertRaises(ValueError, self.manager.get,
                          **{'container_ref': '12345'})

    def test_should_fail_delete_no_href(self):
        self.assertRaises(ValueError, self.manager.delete, None)

    def test_should_register_consumer(self):
        data = self.container.get_dict(self.entity_href,
                                       consumers=[self.container.consumer])

        self.responses.post(self.entity_href + '/consumers/', json=data)
        container = self.manager.register_consumer(
            self.entity_href, self.container.consumer.get('name'),
            self.container.consumer.get('URL')
        )
        self.assertIsInstance(container, containers.Container)
        self.assertEqual(self.entity_href, container.container_ref)

        body = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.consumers_post_resource,
                         self.responses.last_request.url)
        self.assertEqual(self.container.consumer, body)
        self.assertEqual([self.container.consumer], container.consumers)

    def test_should_remove_consumer(self):
        self.responses.delete(self.entity_href + '/consumers', status_code=204)

        self.manager.remove_consumer(
            self.entity_href, self.container.consumer.get('name'),
            self.container.consumer.get('URL')
        )

        body = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.consumers_delete_resource,
                         self.responses.last_request.url)
        self.assertEqual(self.container.consumer, body)

    def test_should_get_total(self):
        self.responses.get(self.entity_base, json={'total': 1})
        total = self.manager.total()
        self.assertEqual(1, total)

    def test_should_get_acls_lazy(self):
        data = self.container.get_dict(self.entity_href,
                                       consumers=[self.container.consumer])
        m = self.responses.get(self.entity_href, json=data)

        acl_data = {'read': {'project-access': True, 'users': ['u2']}}
        acl_ref = self.entity_href + '/acl'
        n = self.responses.get(acl_ref, json=acl_data)

        container = self.manager.get(container_ref=self.entity_href)
        self.assertIsNotNone(container)

        self.assertEqual(self.container.name, container.name)
        # Verify GET was called for secret but for acl it was not called
        self.assertTrue(m.called)
        self.assertFalse(n.called)

        # Check an attribute to trigger lazy-load
        self.assertEqual(['u2'], container.acls.read.users)
        self.assertTrue(container.acls.read.project_access)
        self.assertIsInstance(container.acls, acls.ContainerACL)

        # Verify the correct URL was used to make the GET call
        self.assertEqual(acl_ref, n.last_request.url)

    def test_get_formatted_data(self):
        data = self.container.get_dict(self.entity_href)
        self.responses.get(self.entity_href, json=data)

        container = self.manager.get(container_ref=self.entity_href)

        data = container._get_formatted_data()

        self.assertEqual(self.container.name, data[1])
        self.assertEqual(timeutils.parse_isotime(
                         self.container.created).isoformat(),
                         data[2])
