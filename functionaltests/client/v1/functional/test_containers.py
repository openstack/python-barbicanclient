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
from testtools import testcase
from functionaltests import utils
from functionaltests.client import base
from functionaltests.client.v1.behaviors import container_behaviors
from functionaltests.client.v1.behaviors import secret_behaviors


create_secret_defaults_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
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
    'len_255': [str(bytearray().zfill(255))],
    'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
    'empty': ['']
}


@utils.parameterized_test_case
class BaseContainersTestCase(base.TestCase):

    def setUp(self):
        super(BaseContainersTestCase, self).setUp()

        self.secret_behaviors = secret_behaviors.SecretBehaviors(
            self.barbicanclient)

        self.behaviors = container_behaviors.ContainerBehaviors(
            self.barbicanclient)

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
        self.secret_behaviors.delete_all_created_secrets()
        self.behaviors.delete_all_created_containers()
        super(BaseContainersTestCase, self).tearDown()

    def _create_a_secret(self):
        secret = self.secret_behaviors.create_secret(
            create_secret_defaults_data)
        secret_ref = self.secret_behaviors.store_secret(secret)

        return secret_ref, secret


@utils.parameterized_test_case
class GenericContainersTestCase(BaseContainersTestCase):

    @testcase.attr('positive')
    def test_create_container_defaults_none_secret_name(self):
        """Covers creating a container with None as a secret name."""
        test_model = self.behaviors.create_generic_container(
            create_container_defaults_data)
        test_model.name = None

        container_ref = self.behaviors.store_container(test_model)
        self.assertIsNotNone(container_ref)

    @testcase.attr('negative')
    def test_create_defaults_duplicate_secret_refs(self):
        """Covers creating a container with a duplicated secret ref."""
        secrets = {'secret_1': self.secret_1,
                   'secret_2': self.secret_1,
                   'secret_3': self.secret_1}

        test_model = self.behaviors.create_generic_container(
            create_container_defaults_data, secrets=secrets)

        e = self.assertRaises(Exception, self.behaviors.store_container,
                              test_model)

        self.assertEqual(e.http_status, 400)

    @testcase.attr('negative')
    def test_get_non_existent_container(self):
        """A get on a container that does not exist.

        This should return a container incorrectly specified error since
        the container does not have a correctly formatted UUID
        """
        base_url = self.behaviors.base_url
        url = base_url + '/containers/notauuid'
        e = self.assertRaises(ValueError, self.behaviors.get_container,
                              url)

        self.assertEqual(e.message, 'Container incorrectly specified.')

    @testcase.attr('negative')
    def test_get_non_existent_container_valid_uuid(self):
        """A get on a container that does not exist with valid UUID

        This should return a 404.
        """
        base_url = self.behaviors.base_url
        uuid = 'de305d54-75b4-431b-cccc-eb6b9e546013'
        url = base_url + '/containers/' + uuid

        e = self.assertRaises(Exception, self.behaviors.get_container,
                              url)

        self.assertEqual(e.http_status, 404)

    @testcase.attr('negative')
    def test_delete_non_existent_container(self):
        """A delete on a container that does not exist.

        This should return a container incorrectly specified error since
        the container does not have a correctly formatted UUID
        """
        base_url = self.behaviors.base_url
        url = base_url + '/containers/notauuid'
        e = self.assertRaises(ValueError, self.behaviors.get_container,
                              url)

        self.assertEqual(e.message, 'Container incorrectly specified.')

    @testcase.attr('negative')
    def test_delete_non_existent_container_valid_uuid(self):
        """A delete on a container that does not exist with valid UUID

        This should return a 404.
        """
        uuid = 'de305d54-75b4-431b-cccc-eb6b9e546013'
        base_url = self.barbicanclient.secrets._api._base_url
        url = base_url + '/containers/' + uuid

        e = self.assertRaises(Exception, self.behaviors.get_container,
                              url)

        self.assertEqual(e.http_status, 404)

    @utils.parameterized_dataset({'0': [0], '1': [1], '50': [50]})
    @testcase.attr('positive')
    def test_create_container_defaults_size(self, num_secrets):
        """Covers creating containers of various sizes."""
        secrets = {}
        for i in range(0, num_secrets):
            secret_ref, secret = self._create_a_secret()
            secrets['other_secret{0}'.format(i)] = secret

        test_model = self.behaviors.create_generic_container(
            create_container_defaults_data,
            secrets=secrets)

        container_ref = self.behaviors.store_container(test_model)
        self.assertIsNotNone(container_ref)

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_container_defaults_name(self, name):
        """Covers creating generic containers with various names."""
        test_model = self.behaviors.create_generic_container(
            create_container_defaults_data)
        test_model.name = name

        container_ref = self.behaviors.store_container(test_model)
        self.assertIsNotNone(container_ref)

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_container_defaults_secret_name(self, name=None):
        """Covers creating containers with various secret ref names."""
        secrets = {name: self.secret_1}

        test_model = self.behaviors.create_generic_container(
            create_container_defaults_data,
            secrets=secrets)

        container_ref = self.behaviors.store_container(test_model)
        self.assertIsNotNone(container_ref)

        get_resp = self.behaviors.get_container(container_ref)
        self.assertIsNotNone(get_resp.secret_refs.get(name))


@utils.parameterized_test_case
class RSAContainersTestCase(BaseContainersTestCase):
    @testcase.attr('positive')
    def test_create_containers_rsa_no_passphrase(self):
        """Covers creating an rsa container without a passphrase."""

        test_model = self.behaviors.create_rsa_container(
            create_container_rsa_data,
            disable_passphrase=True)

        container_ref = self.behaviors.store_container(test_model)
        self.assertIsNotNone(container_ref)

        get_resp = self.behaviors.get_container(container_ref)
        self.assertIsNone(get_resp.private_key_passphrase)
        self.assertEqual(len(get_resp.secrets), 2)

    @utils.parameterized_dataset(accepted_str_values)
    @testcase.attr('positive')
    def test_create_container_rsa_name(self, name):
        """Covers creating rsa containers with various names."""
        test_model = self.behaviors.create_rsa_container(
            create_container_rsa_data)
        test_model.name = name

        container_ref = self.behaviors.store_container(test_model)
        self.assertIsNotNone(container_ref)

        get_resp = self.behaviors.get_container(container_ref)
        self.assertEqual(get_resp.name, name)

    @testcase.attr('negative')
    def test_create_rsa_invalid_key_names(self):
        """Covers creating an RSA container with incorrect names."""
        incorrect_names_rsa_container = {
            "name": "bad_container",
            "secret1": self.secret_ref_1,
            "secret2": self.secret_ref_2,
            "secret3": self.secret_ref_3
        }

        e = self.assertRaises(TypeError, self.behaviors.create_rsa_container,
                              incorrect_names_rsa_container)

        self.assertIn('got an unexpected keyword argument', e.message)

    @testcase.attr('negative')
    def test_create_rsa_no_public_key(self):
        """Creating an rsa container without a public key should fail.

        RSA containers must have at least a public key and private key.
        """
        no_public_key_rsa_container = {"name": "no_pub_key",
                                       "private_key": self.secret_1,
                                       "private_key_passphrase": self.secret_2,
                                       }

        test_model = self.behaviors.create_rsa_container(
            no_public_key_rsa_container)

        e = self.assertRaises(Exception, self.behaviors.store_container,
                              test_model)

        self.assertEqual(e.http_status, 400)

    @testcase.attr('negative')
    def test_create_rsa_no_private_key(self):
        """Creating an rsa container without a private key should fail.

        RSA containers must have at least a public key and private key.
        """
        no_private_key_rsa_container = {
            "name": "no_pub_key",
            "public_key": self.secret_1,
            "private_key_passphrase": self.secret_2}

        test_model = self.behaviors.create_rsa_container(
            no_private_key_rsa_container)

        e = self.assertRaises(Exception, self.behaviors.store_container,
                              test_model)

        self.assertEqual(e.http_status, 400)
