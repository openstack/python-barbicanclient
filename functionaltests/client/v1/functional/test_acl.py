# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
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

from functionaltests.client import base
from functionaltests.common import cleanup
from functionaltests import utils
from oslo_utils import uuidutils

from barbicanclient import exceptions


create_secret_defaults_data = {
    "name": "AES key",
    "expiration": "2030-02-28T19:14:44.180394",
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


ACL_SUBMIT_DATA_POSITIVE = {
    'secret_no_users_access_flag': {
        'users': None, 'project_access': True,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'expect_users': [], 'expect_project_access': True},

    'secret_users_missing_access_flag': {
        'users': ['u1', 'u2'], 'project_access': None,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'expect_users': ['u1', 'u2'], 'expect_project_access': True},

    'container_users_no_project_access': {
        'users': ['u1', 'u2', 'u3'], 'project_access': False,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'expect_users': ['u1', 'u2', 'u3'], 'expect_project_access': False},

    'container_empty_users_with_project_access': {
        'users': [], 'project_access': True,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'expect_users': [], 'expect_project_access': True},
}

ACL_SUBMIT_DATA_NEGATIVE = {
    'secret_users_incorrect_access_flag': {
        'users': ['u1', 'u2'], 'project_access': 'Incorrect_flag',
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'expect_users': ['u1', 'u2'], 'expect_project_access': True,
        'expect_error': True, 'error_code': 400},

    'container_incorrect_users_as_str': {
        'users': 'u1', 'project_access': True,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'expect_users': ['u1'], 'expect_project_access': True,
        'expect_error': True, 'error_code': None, 'error_class': ValueError},
}

ACL_DELETE_DATA = {
    'secret_no_users_access_flag': {
        'users': None, 'project_access': True, 'create_acl': True,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'expect_users': [], 'expect_project_access': True},

    'secret_users_missing_access_flag': {
        'users': ['u1', 'u2'], 'project_access': None, 'create_acl': True,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'expect_users': [], 'expect_project_access': True},

    'container_users_no_project_access': {
        'users': ['u1', 'u2', 'u3'], 'project_access': False,
        'create_acl': True,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'expect_users': [], 'expect_project_access': True},

    'container_empty_users_with_project_access': {
        'users': [], 'project_access': True, 'create_acl': True,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'expect_users': [], 'expect_project_access': True},

    'existing_secret_no_acl_defined': {
        'users': ['u1', 'u2'], 'project_access': False, 'create_acl': False,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'expect_users': [], 'expect_project_access': True,
        'expect_error': False},

    'acl_operation_specific_remove': {
        'users': ['u1', 'u2', 'u3'], 'project_access': False,
        'create_acl': True, 'per_op_acl_remove': True,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'expect_users': [], 'expect_project_access': True},
}

ACL_ADD_USERS_DATA_POSITIVE = {
    'secret_no_initial_users_access_flag': {
        'users': None, 'project_access': True,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'add_users': ['u4'],
        'expect_users': ['u4'], 'expect_project_access': True},

    'secret_users_missing_access_flag': {
        'users': ['u1', 'u2'], 'project_access': None,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'add_users': ['u2', 'u4'],
        'expect_users': ['u1', 'u2', 'u4'], 'expect_project_access': True},

    'container_users_no_project_access_empty_add': {
        'users': ['u1', 'u2', 'u3'], 'project_access': False,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'add_users': [],
        'expect_users': ['u1', 'u2', 'u3'], 'expect_project_access': False},

    'container_empty_users_with_project_access_none_add_users': {
        'users': [], 'project_access': True,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'add_users': None,
        'expect_users': [], 'expect_project_access': True},

    'secret_users_modify_access_flag_in_add': {
        'users': ['u1', 'u2', 'u3'], 'project_access': False,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'add_users': [], 'add_project_access': True,
        'expect_users': ['u1', 'u2', 'u3'], 'expect_project_access': True},

}

ACL_ADD_USERS_DATA_NEGATIVE = {
    'secret_users_incorrect_access_flag_during_add': {
        'users': ['u1', 'u2'], 'project_access': False,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'add_users': ['u5'], 'add_project_access': 'Incorrect',
        'expect_users': ['u1', 'u2', 'u5'], 'expect_project_access': False,
        'expect_error': True, 'error_code': 400},
}

ACL_REMOVE_USERS_DATA_POSITIVE = {
    'secret_no_initial_users_access_flag': {
        'users': None, 'project_access': True,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'remove_users': ['u4'],
        'expect_users': [], 'expect_project_access': True},

    'secret_users_missing_access_flag': {
        'users': ['u1', 'u2'], 'project_access': None,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'remove_users': ['u2', 'u4'],
        'expect_users': ['u1'], 'expect_project_access': True},

    'secret_users_no_matching_users': {
        'users': ['u1', 'u2'], 'project_access': None,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'remove_users': ['u3', 'u4'],
        'expect_users': ['u1', 'u2'], 'expect_project_access': True},

    'container_users_no_project_access_empty_add': {
        'users': ['u1', 'u2', 'u3'], 'project_access': False,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'remove_users': [],
        'expect_users': ['u1', 'u2', 'u3'], 'expect_project_access': False},

    'container_empty_users_with_project_access_none_add_users': {
        'users': [], 'project_access': True,
        'entity_ref_method': '_create_a_container', 'acl_type': 'container',
        'remove_users': None,
        'expect_users': [], 'expect_project_access': True},

    'secret_users_modify_access_flag_in_remove': {
        'users': ['u1', 'u2', 'u3'], 'project_access': False,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'remove_users': [], 'remove_project_access': True,
        'expect_users': ['u1', 'u2', 'u3'], 'expect_project_access': True},
}

ACL_REMOVE_USERS_DATA_NEGATIVE = {
    'secret_users_incorrect_access_flag_during_add': {
        'users': ['u1', 'u2'], 'project_access': False,
        'entity_ref_method': '_create_a_secret', 'acl_type': 'secret',
        'remove_users': ['u5'], 'remove_project_access': 'Incorrect',
        'expect_users': ['u1', 'u2'], 'expect_project_access': False,
        'expect_error': True, 'error_code': 400},
}


class BaseACLsTestCase(base.TestCase):

    def setUp(self):
        super(BaseACLsTestCase, self).setUp()

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
        super(BaseACLsTestCase, self).tearDown()

    def _create_a_secret(self):
        secret = self.barbicanclient.secrets.create(
            **create_secret_defaults_data)
        secret_ref = self.cleanup.add_entity(secret)

        return secret_ref, secret

    def _create_a_container(self):
        container = self.barbicanclient.containers.create(
            **create_container_defaults_data)
        container_ref = self.cleanup.add_entity(container)

        return container_ref, container


@utils.parameterized_test_case
class ACLsTestCase(BaseACLsTestCase):

    @testcase.attr('negative')
    def test_get_non_existent_secret_valid_uuid(self):
        """A get on a container that does not exist with valid UUID

        This should return a 404.
        """
        base_url = self.barbicanclient.acls._api.endpoint_override
        new_uuid = uuidutils.generate_uuid()
        url = '{0}/containers/{1}'.format(base_url, new_uuid)

        e = self.assertRaises(
            exceptions.HTTPClientError,
            self.barbicanclient.acls.get,
            url
        )

        self.assertEqual(404, e.status_code)

    @testcase.attr('negative')
    def test_delete_non_existent_secret_valid_uuid(self):
        """A delete on an ACL when secret with a valid UUID does not exist

        This should return a 404.
        """
        base_url = self.barbicanclient.acls._api.endpoint_override
        new_uuid = uuidutils.generate_uuid()
        url = '{0}/secrets/{1}'.format(base_url, new_uuid)

        acl_data = {'entity_ref': url}
        entity = self.barbicanclient.acls.create(**acl_data)

        e = self.assertRaises(
            exceptions.HTTPClientError,
            entity.remove
        )

        self.assertEqual(404, e.status_code)

    @utils.parameterized_dataset(ACL_SUBMIT_DATA_POSITIVE)
    @testcase.attr('positive')
    def test_acl_successful_submit(self, users, project_access,
                                   entity_ref_method, acl_type,
                                   expect_users, expect_project_access,
                                   **kwargs):
        """Submit operation on ACL entity which stores ACL setting in Barbican.

        """
        entity_ref, _ = getattr(self, entity_ref_method)()

        acl_data = {'entity_ref': entity_ref, 'users': users,
                    'project_access': project_access}
        entity = self.barbicanclient.acls.create(**acl_data)

        acl_ref = self.cleanup.add_entity(entity)
        self.assertIsNotNone(acl_ref)
        self.assertEqual(entity_ref + "/acl", acl_ref)

        acl_entity = self.barbicanclient.acls.get(entity.entity_ref)
        self.assertIsNotNone(acl_entity)

        # read acl as dictionary lookup
        acl = acl_entity.get('read')
        self.assertEqual(set(expect_users), set(acl.users))
        self.assertEqual(expect_project_access, acl.project_access)
        self.assertIsNotNone(acl.created)
        self.assertIsNotNone(acl.updated)
        self.assertEqual(acl_type, acl_entity._acl_type)

        # read acl as property lookup
        acl = acl_entity.read
        self.assertEqual(set(expect_users), set(acl.users))
        self.assertEqual(expect_project_access, acl.project_access)

    @utils.parameterized_dataset(ACL_SUBMIT_DATA_NEGATIVE)
    @testcase.attr('negative')
    def test_acl_incorrect_submit(self, users, project_access,
                                  entity_ref_method, acl_type, expect_users,
                                  expect_project_access, **kwargs):
        """Check incorrect submit operation failure on ACL entity."""
        entity_ref, _ = getattr(self, entity_ref_method)()

        acl_data = {'entity_ref': entity_ref, 'users': users,
                    'project_access': project_access}
        entity = self.barbicanclient.acls.create(**acl_data)

        error_class = kwargs.get('error_class', exceptions.HTTPClientError)
        e = self.assertRaises(
            error_class,
            entity.submit
        )
        if hasattr(e, 'status_code'):
            self.assertEqual(kwargs.get('error_code'), e.status_code)

    @utils.parameterized_dataset(ACL_DELETE_DATA)
    def test_acl_delete(self, users, project_access, entity_ref_method,
                        create_acl, acl_type, expect_users,
                        expect_project_access, **kwargs):
        """remove operation on ACL entity which stores ACL setting in Barbican.

        """
        entity_ref, _ = getattr(self, entity_ref_method)()

        acl_data = {'entity_ref': entity_ref, 'users': users,
                    'project_access': project_access}
        entity = self.barbicanclient.acls.create(**acl_data)

        entity_ref = entity.entity_ref
        if create_acl:
            self.cleanup.add_entity(entity)

        acl_op_remove = kwargs.get('per_op_acl_remove')
        if acl_op_remove:
            entity.read.remove()
        else:
            entity.remove()

        acl_entity = self.barbicanclient.acls.get(entity_ref)
        self.assertIsNotNone(acl_entity)

        # read acl as dictionary lookup
        acl = acl_entity.get('read')
        self.assertEqual(set(expect_users), set(acl.users))
        self.assertEqual(expect_project_access, acl.project_access)
        self.assertIsNone(acl.created)
        self.assertIsNone(acl.updated)
        self.assertEqual(acl_type, acl_entity._acl_type)

        # read acl as property lookup
        acl = acl_entity.read
        self.assertEqual(set(expect_users), set(acl.users))
        self.assertEqual(expect_project_access, acl.project_access)

    @utils.parameterized_dataset(ACL_ADD_USERS_DATA_POSITIVE)
    @testcase.attr('positive')
    def test_acl_successful_add_users(self, users, project_access,
                                      entity_ref_method, acl_type, add_users,
                                      expect_users, expect_project_access,
                                      **kwargs):
        """Checks client add users behavior on existing ACL entity.

        In this new users or project access flag is modified and verified for
        expected behavior
        """
        entity_ref, _ = getattr(self, entity_ref_method)()

        acl_data = {'entity_ref': entity_ref, 'users': users,
                    'project_access': project_access}
        entity = self.barbicanclient.acls.create(**acl_data)

        acl_ref = self.cleanup.add_entity(entity)
        self.assertIsNotNone(acl_ref)
        self.assertEqual(entity_ref + "/acl", acl_ref)

        server_acl = self.barbicanclient.acls.get(entity.entity_ref)

        if server_acl.get('read').users is not None and add_users:
            server_acl.get('read').users.extend(add_users)

        if kwargs.get('add_project_access') is not None:
            server_acl.get('read').project_access = \
                kwargs.get('add_project_access')

        acl_ref = server_acl.submit()
        self.assertIsNotNone(acl_ref)
        self.assertEqual(entity_ref + "/acl", acl_ref)

        acl_entity = self.barbicanclient.acls.get(server_acl.entity_ref)
        self.assertIsNotNone(acl_entity)

        # read acl as dictionary lookup
        acl = acl_entity.get('read')
        self.assertEqual(set(expect_users), set(acl.users))
        self.assertEqual(expect_project_access, acl.project_access)
        self.assertIsNotNone(acl.created)
        self.assertIsNotNone(acl.updated)
        self.assertEqual(acl_type, acl_entity._acl_type)

        # read acl as property lookup
        acl = acl_entity.read
        self.assertEqual(set(expect_users), set(acl.users))
        self.assertEqual(expect_project_access, acl.project_access)

    @utils.parameterized_dataset(ACL_ADD_USERS_DATA_NEGATIVE)
    @testcase.attr('negative')
    def test_acl_add_users_failure(self, users, project_access,
                                   entity_ref_method, acl_type, add_users,
                                   expect_users, expect_project_access,
                                   **kwargs):
        """Checks client add users failures on existing ACL entity.

        In this new users or project access flag is modified and verified for
        expected behavior
        """
        entity_ref, _ = getattr(self, entity_ref_method)()

        acl_data = {'entity_ref': entity_ref, 'users': users,
                    'project_access': project_access}
        entity = self.barbicanclient.acls.create(**acl_data)

        acl_ref = self.cleanup.add_entity(entity)
        self.assertIsNotNone(acl_ref)
        self.assertEqual(entity_ref + "/acl", acl_ref)

        server_acl = self.barbicanclient.acls.get(entity.entity_ref)

        if server_acl.get('read').users is not None and add_users:
            server_acl.get('read').users.extend(add_users)

        if kwargs.get('add_project_access') is not None:
            server_acl.get('read').project_access = \
                kwargs.get('add_project_access')

        error_class = kwargs.get('error_class', exceptions.HTTPClientError)
        e = self.assertRaises(
            error_class,
            server_acl.submit
        )
        if hasattr(e, 'status_code'):
            self.assertEqual(kwargs.get('error_code'), e.status_code)

    @utils.parameterized_dataset(ACL_REMOVE_USERS_DATA_POSITIVE)
    @testcase.attr('positive')
    def test_acl_remove_users_successful(self, users, project_access,
                                         entity_ref_method, acl_type,
                                         remove_users, expect_users,
                                         expect_project_access, **kwargs):
        """Checks client remove users behavior on existing ACL entity.

        In this users are removed from existing users list or project access
        flag is modified and then verified for expected behavior
        """
        entity_ref, _ = getattr(self, entity_ref_method)()

        acl_data = {'entity_ref': entity_ref, 'users': users,
                    'project_access': project_access}
        entity = self.barbicanclient.acls.create(**acl_data)

        acl_ref = self.cleanup.add_entity(entity)
        self.assertIsNotNone(acl_ref)
        self.assertEqual(entity_ref + "/acl", acl_ref)

        server_acl = self.barbicanclient.acls.get(entity.entity_ref)
        acl_users = server_acl.read.users
        if acl_users and remove_users:
            acl_users = set(acl_users).difference(remove_users)
            # Python sets are not JSON serializable. Cast acl_users to a list.
            server_acl.read.users = list(acl_users)

        if kwargs.get('remove_project_access') is not None:
            server_acl.read.project_access = \
                kwargs.get('remove_project_access')

        acl_ref = server_acl.submit()
        self.assertIsNotNone(acl_ref)
        self.assertEqual(entity_ref + "/acl", acl_ref)

        acl_entity = self.barbicanclient.acls.get(server_acl.entity_ref)
        self.assertIsNotNone(acl_entity)

        # read acl as dictionary lookup
        acl = acl_entity.get('read')
        self.assertEqual(set(expect_users), set(acl.users))
        self.assertEqual(expect_project_access, acl.project_access)
        self.assertIsNotNone(acl.created)
        self.assertIsNotNone(acl.updated)
        self.assertEqual(acl_type, acl_entity._acl_type)

        # read acl as property lookup
        acl = acl_entity.read
        self.assertEqual(set(expect_users), set(acl.users))
        self.assertEqual(expect_project_access, acl.project_access)

    @utils.parameterized_dataset(ACL_REMOVE_USERS_DATA_NEGATIVE)
    @testcase.attr('negative')
    def test_acl_remove_users_failure(self, users, project_access,
                                      entity_ref_method, acl_type,
                                      remove_users, expect_users,
                                      expect_project_access, **kwargs):
        """Checks client remove users failures on existing ACL entity.

        In this users are removed from existing users list or project access
        flag is modified and then verified for expected behavior
        """
        entity_ref, _ = getattr(self, entity_ref_method)()

        acl_data = {'entity_ref': entity_ref, 'users': users,
                    'project_access': project_access}
        entity = self.barbicanclient.acls.create(**acl_data)

        acl_ref = self.cleanup.add_entity(entity)
        self.assertIsNotNone(acl_ref)
        self.assertEqual(entity_ref + "/acl", acl_ref)

        server_acl = self.barbicanclient.acls.get(entity.entity_ref)
        acl_users = server_acl.read.users
        if acl_users and remove_users:
            acl_users = set(acl_users).difference(remove_users)
            # Python sets are not JSON serializable. Cast acl_users to a list.
            server_acl.read.users = list(acl_users)

        if kwargs.get('remove_project_access') is not None:
            server_acl.read.project_access = \
                kwargs.get('remove_project_access')

        error_class = kwargs.get('error_class', exceptions.HTTPClientError)
        e = self.assertRaises(
            error_class,
            server_acl.submit
        )
        if hasattr(e, 'status_code'):
            self.assertEqual(kwargs.get('error_code'), e.status_code)
