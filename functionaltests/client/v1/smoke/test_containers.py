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


@utils.parameterized_test_case
class ContainersTestCase(base.TestCase):

    def setUp(self):
        super(ContainersTestCase, self).setUp()

        self.cleanup = cleanup.CleanUp(self.barbicanclient)

        # Set up three secrets
        secret_ref_1, secret_1 = self._create_a_secret()
        secret_ref_2, secret_2 = self._create_a_secret()
        secret_ref_3, secret_3 = self._create_a_secret()

        self.secret_list = [secret_ref_1, secret_ref_2, secret_ref_3]

        secrets_dict = {'secret_1': secret_1, 'secret_2': secret_2,
                        'secret_3': secret_3}

        create_container_defaults_data['secrets'] = secrets_dict

        create_container_rsa_data['public_key'] = secret_1
        create_container_rsa_data['private_key'] = secret_2
        create_container_rsa_data['private_key_passphrase'] = secret_3

    def tearDown(self):
        """Handles test cleanup.

        It should be noted that delete all secrets must be called before
        delete containers.
        """
        self.cleanup.delete_all_entities()
        super(ContainersTestCase, self).tearDown()

    def _create_a_secret(self):
        secret = self.barbicanclient.secrets.create(
            **create_secret_defaults_data)
        secret_ref = self.cleanup.add_entity(secret)

        return secret_ref, secret

    @testcase.attr('positive')
    def test_container_create_empty(self):
        """Covers creating an empty generic container."""
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

    @testcase.attr('positive')
    def test_container_create_defaults(self):
        """Covers creating a container with three secret refs."""
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

    @testcase.attr('positive')
    def test_container_create_rsa(self):
        """Create an RSA container with expected secret refs."""
        container = self.barbicanclient.containers.create_rsa(
            **create_container_rsa_data)

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

    @utils.parameterized_dataset({
        'alphanumeric': ['a2j3j6ll9'],
        'punctuation': ['~!@#$%^&*()_+`-={}[]|:;<>,.?'],
        'len_255': [str(bytearray().zfill(255))],
        'uuid': ['54262d9d-4bc7-4821-8df0-dc2ca8e112bb'],
        'empty': ['']
    })
    @testcase.attr('positive')
    def test_container_get_defaults_w_valid_name(self, name):
        """Covers getting a generic container with a three secrets."""
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)
        container.name = name

        secret_refs = self.secret_list

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

        container_resp = self.barbicanclient.containers.get(container_ref)

        # Verify the response data
        self.assertEqual(container.name, container_resp.name)
        self.assertEqual(container_ref, container_resp.container_ref)

        get_resp_secret_refs = []
        for name, ref in container_resp.secret_refs.iteritems():
            get_resp_secret_refs.append(str(ref))

        # Verify the secret refs in the response
        self.assertEqual(3, len(container_resp.secret_refs))
        self.assertIn(secret_refs[0], get_resp_secret_refs)
        self.assertIn(secret_refs[1], get_resp_secret_refs)
        self.assertIn(secret_refs[2], get_resp_secret_refs)

    @testcase.attr('positive')
    def test_container_get_rsa(self):
        """Covers getting an rsa container."""
        container = self.barbicanclient.containers.create_rsa(
            **create_container_rsa_data)

        secret_refs = self.secret_list

        container_ref = self.cleanup.add_entity(container)
        self.assertIsNotNone(container_ref)

        container_resp = self.barbicanclient.containers.get(container_ref)

        # Verify the response data
        self.assertEqual("rsacontainer", container_resp.name)
        self.assertEqual(container_ref, container_resp.container_ref)

        get_resp_secret_refs = []
        for name, ref in container_resp.secret_refs.iteritems():
            get_resp_secret_refs.append(str(ref))
        # Verify the secret refs in the response
        self.assertEqual(3, len(container_resp.secret_refs))
        self.assertIn(secret_refs[0], get_resp_secret_refs)
        self.assertIn(secret_refs[1], get_resp_secret_refs)
        self.assertIn(secret_refs[2], get_resp_secret_refs)

    @testcase.attr('positive')
    def test_containers_get_defaults(self):
        """Covers getting a list of containers."""
        limit = 10
        offset = 0
        total = 10

        for i in range(0, total + 1):
            container = self.barbicanclient.containers.create(
                **create_container_defaults_data)
            container_ref = self.cleanup.add_entity(container)
            self.assertIsNotNone(container_ref)

        containers = self.barbicanclient.containers.list(limit=limit,
                                                         offset=offset)

        self.assertEqual(limit, len(containers))

    def test_container_delete_defaults(self):
        """Covers deleting a container."""
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)

        container_ref = container.store()
        self.assertIsNotNone(container_ref)

        del_resp = self.barbicanclient.containers.delete(container_ref)
        self.assertIsNone(del_resp)
