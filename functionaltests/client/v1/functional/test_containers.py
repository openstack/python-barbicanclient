# Copyright (c) 2015 Rackspace, Inc.
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
from functionaltests.client import base
from functionaltests.common import cleanup
from functionaltests import utils
from testtools import testcase

from barbicanclient import exceptions


create_secret_defaults_data = {
    "name": "AES key",
    "expiration": "2030-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": b"gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

create_container_defaults_data = {
    "name": "containername",
    "secrets": {}
}

create_container_rsa_data = {
    "name": "rsacontainer",
}

create_container_empty_data = {
    "name": None,
    "secrets": {}
}

accepted_str_values = {
    'alphanumeric': ['a2j3j6ll9'],
    'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
    'len_255': ['a' * 255],
    'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
    'empty': ['']
}


@utils.parameterized_test_case
class BaseContainersTestCase(base.TestCase):

    def setUp(self):
        super(BaseContainersTestCase, self).setUp()

        self.cleanup = cleanup.CleanUp(self.barbicanclient)

        # Set up three secrets
        self.secret_ref_1, self.secret_1 = self._create_a_secret()
        self.secret_ref_2, self.secret_2 = self._create_a_secret()
        self.secret_ref_3, self.secret_3 = self._create_a_secret()

        self.secret_list = [self.secret_ref_1, self.secret_ref_2,
                            self.secret_ref_3]

        secrets_dict = {'secret_1': self.secret_1, 'secret_2': self.secret_2,
                        'secret_3': self.secret_3}

        create_container_defaults_data['secrets'] = secrets_dict

        create_container_rsa_data['public_key'] = self.secret_1
        create_container_rsa_data['private_key'] = self.secret_2
        create_container_rsa_data['private_key_passphrase'] = self.secret_3

    def tearDown(self):
        """Handles test cleanup.

        It should be noted that delete all secrets must be called before
        delete containers.
        """
        self.cleanup.delete_all_entities()
        super(BaseContainersTestCase, self).tearDown()

    def _create_a_secret(self):
        secret = self.barbicanclient.secrets.create(
            **create_secret_defaults_data)
        secret_ref = self.cleanup.add_entity(secret)

        return secret_ref, secret


@utils.parameterized_test_case
class GenericContainersTestCase(BaseContainersTestCase):

    @testcase.attr('positive')
    def test_create_container_defaults_none_secret_name(self):
        """Covers creating a container with None as a secret name."""
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)
        container.name = None

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

    @testcase.attr('negative')
    def test_create_defaults_duplicate_secret_refs(self):
        """Covers creating a container with a duplicated secret ref."""
        secrets = {'secret_1': self.secret_1,
                   'secret_2': self.secret_1,
                   'secret_3': self.secret_1}

        create_container_defaults_data['secrets'] = secrets
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)

        e = self.assertRaises(
            exceptions.HTTPClientError,
            container.store
        )

        self.assertEqual(400, e.status_code)

    @testcase.attr('negative')
    def test_get_non_existent_container(self):
        """A get on a container that does not exist.

        This should return a container incorrectly specified error since
        the container does not have a correctly formatted UUID
        """
        base_url = self.barbicanclient.containers._api.endpoint_override
        url = base_url + '/containers/notauuid'
        e = self.assertRaises(ValueError, self.barbicanclient.containers.get,
                              url)

        self.assertEqual('Container incorrectly specified.', str(e))

    @testcase.attr('negative')
    def test_get_non_existent_container_valid_uuid(self):
        """A get on a container that does not exist with valid UUID

        This should return a 404.
        """
        base_url = self.barbicanclient.containers._api.endpoint_override
        uuid = 'de305d54-75b4-431b-cccc-eb6b9e546013'
        url = base_url + '/containers/' + uuid

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.barbicanclient.containers.get,
            url
        )

        self.assertEqual(404, e.status_code)

    @testcase.attr('negative')
    def test_delete_non_existent_container(self):
        """A delete on a container that does not exist.

        This should return a container incorrectly specified error since
        the container does not have a correctly formatted UUID
        """
        base_url = self.barbicanclient.containers._api.endpoint_override
        url = base_url + '/containers/notauuid'
        e = self.assertRaises(ValueError, self.barbicanclient.containers.get,
                              url)

        self.assertEqual('Container incorrectly specified.', str(e))

    @testcase.attr('negative')
    def test_delete_non_existent_container_valid_uuid(self):
        """A delete on a container that does not exist with valid UUID

        This should return a 404.
        """
        uuid = 'de305d54-75b4-431b-cccc-eb6b9e546013'
        base_url = self.barbicanclient.containers._api.endpoint_override
        url = base_url + '/containers/' + uuid

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.barbicanclient.containers.get,
            url
        )

        self.assertEqual(404, e.status_code)

    @utils.parameterized_dataset({'0': [0], '1': [1], '50': [50]})
    @testcase.attr('positive')
    def test_create_container_defaults_size(self, num_secrets):
        """Covers creating containers of various sizes."""
        secrets = {}
        for i in range(0, num_secrets):
            secret_ref, secret = self._create_a_secret()
            secrets['other_secret{0}'.format(i)] = secret

        create_container_defaults_data['secrets'] = secrets
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_container_defaults_name(self, name):
        """Covers creating generic containers with various names."""
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)
        container.name = name

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_container_defaults_secret_name(self, name=None):
        """Covers creating containers with various secret ref names."""
        secrets = {name: self.secret_1}

        create_container_defaults_data['secrets'] = secrets
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

        container_resp = self.barbicanclient.containers.get(container_ref)
        self.assertIsNotNone(container_resp.secret_refs.get(name))

    @testcase.attr('positive')
    def test_container_read_with_acls(self):
        """Access default ACL settings data on recently created container.

        By default, 'read' ACL settings are there for a container.
         """
        test_model = self.barbicanclient.containers.create(
            **create_container_defaults_data)

        container_ref = self.cleanup.add_entity(test_model)
        self.assertIsNotNone(container_ref)

        container_entity = self.barbicanclient.containers.get(container_ref)
        self.assertIsNotNone(container_entity.acls)
        self.assertIsNotNone(container_entity.acls.read)
        self.assertEqual([], container_entity.acls.read.users)

    @utils.parameterized_dataset({
        'remove_one': [[{'name': 'ab', 'URL': 'http://c.d/e/1'},
                        {'name': 'ab', 'URL': 'http://c.d/e/2'}],
                       [{'name': 'ab', 'URL': 'http://c.d/e/1'}]],
        'remove_all': [[{'name': 'ab', 'URL': 'http://c.d/e/1'},
                        {'name': 'ab', 'URL': 'http://c.d/e/2'}],
                       [{'name': 'ab', 'URL': 'http://c.d/e/1'},
                        {'name': 'ab', 'URL': 'http://c.d/e/2'}]]
    })
    @testcase.attr('positive')
    def test_container_create_and_registering_removing_consumers(
            self,
            register_consumers,
            remove_consumers):

        new_container = self.barbicanclient.containers.create(
            **create_container_defaults_data)

        container_ref = self.cleanup.add_entity(new_container)
        self.assertIsNotNone(container_ref)

        for consumer in register_consumers:
            container = self.barbicanclient.containers.register_consumer(
                container_ref, consumer['name'], consumer['URL'])
            self.assertEqual(container_ref, container.container_ref)
        self.assertCountEqual(register_consumers, container.consumers)

        for consumer in remove_consumers:
            self.barbicanclient.containers.remove_consumer(
                container_ref, consumer['name'], consumer['URL'])

        container = self.barbicanclient.containers.get(container_ref)

        removed_urls = set([v['URL'] for v in remove_consumers])
        remaining_consumers = [v for v in register_consumers
                               if v['URL'] not in removed_urls]
        self.assertCountEqual(remaining_consumers, container.consumers)


@utils.parameterized_test_case
class RSAContainersTestCase(BaseContainersTestCase):
    @testcase.attr('positive')
    def test_create_containers_rsa_no_passphrase(self):
        """Covers creating an rsa container without a passphrase."""
        create_container_rsa_data['private_key_passphrase'] = None
        container = self.barbicanclient.containers.create_rsa(
            **create_container_rsa_data)

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

        container_resp = self.barbicanclient.containers.get(container_ref)
        self.assertIsNone(container_resp.private_key_passphrase)
        self.assertEqual(2, len(container_resp.secrets))

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_container_rsa_name(self, name):
        """Covers creating rsa containers with various names."""
        container = self.barbicanclient.containers.create_rsa(
            **create_container_rsa_data)
        container.name = name

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

        container_resp = self.barbicanclient.containers.get(container_ref)
        self.assertEqual(name, container_resp.name)

    @testcase.attr('negative')
    def test_create_rsa_invalid_key_names(self):
        """Covers creating an RSA container with incorrect names."""
        incorrect_names_rsa_container = {
            "name": "bad_container",
            "secret1": self.secret_ref_1,
            "secret2": self.secret_ref_2,
            "secret3": self.secret_ref_3
        }

        e = self.assertRaises(TypeError,
                              self.barbicanclient.containers.create_rsa,
                              **incorrect_names_rsa_container)

        self.assertIn('got an unexpected keyword argument', str(e))

    @testcase.attr('negative')
    def test_create_rsa_no_public_key(self):
        """Creating an rsa container without a public key should fail.

        RSA containers must have at least a public key and private key.
        """
        no_public_key_rsa_container = {"name": "no_pub_key",
                                       "private_key": self.secret_1,
                                       "private_key_passphrase": self.secret_2,
                                       }

        container = self.barbicanclient.containers.create_rsa(
            **no_public_key_rsa_container)

        e = self.assertRaises(
            exceptions.HTTPClientError,
            container.store
        )

        self.assertEqual(400, e.status_code)

    @testcase.attr('negative')
    def test_create_rsa_no_private_key(self):
        """Creating an rsa container without a private key should fail.

        RSA containers must have at least a public key and private key.
        """
        no_private_key_rsa_container = {
            "name": "no_pub_key",
            "public_key": self.secret_1,
            "private_key_passphrase": self.secret_2}

        container = self.barbicanclient.containers.create_rsa(
            **no_private_key_rsa_container)

        e = self.assertRaises(
            exceptions.HTTPClientError,
            container.store
        )

        self.assertEqual(400, e.status_code)
