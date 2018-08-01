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

from oslo_utils import timeutils
import requests_mock

from barbicanclient.tests import test_client
from barbicanclient.v1 import acls


class ACLTestCase(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('acl', entity_id='d9f95d61-8863-49d3-a045-5c2cb77130b5')

        self.secret_uuid = '8a3108ec-88fc-4f5c-86eb-f37b8ae8358e'
        self.secret_ref = (self.endpoint + '/v1/secrets/' + self.secret_uuid)
        self.secret_acl_ref = '{0}/acl'.format(self.secret_ref)

        self.container_uuid = '83c302c7-86fe-4f07-a277-c4962f121f19'
        self.container_ref = (self.endpoint + '/v1/containers/' +
                              self.container_uuid)
        self.container_acl_ref = '{0}/acl'.format(self.container_ref)

        self.manager = self.client.acls
        self.users1 = ['2d0ee7c681cc4549b6d76769c320d91f',
                       '721e27b8505b499e8ab3b38154705b9e']
        self.users2 = ['2d0ee7c681cc4549b6d76769c320d91f']
        self.created = str(timeutils.utcnow())

    def get_acl_response_data(self, operation_type='read',
                              users=None,
                              project_access=False):
        if users is None:
            users = self.users1
        op_data = {'users': users}
        op_data['project-access'] = project_access
        op_data['created'] = self.created
        op_data['updated'] = str(timeutils.utcnow())
        acl_data = {operation_type: op_data}
        return acl_data


class WhenTestingACLManager(ACLTestCase):

    def test_should_get_secret_acl(self, entity_ref=None):
        entity_ref = entity_ref or self.secret_ref
        self.responses.get(self.secret_acl_ref,
                           json=self.get_acl_response_data())

        api_resp = self.manager.get(entity_ref=entity_ref)
        self.assertEqual(self.secret_acl_ref,
                         self.responses.last_request.url)
        self.assertFalse(api_resp.get('read').project_access)
        self.assertEqual('read', api_resp.get('read').operation_type)
        self.assertIn(api_resp.get('read').acl_ref_relative,
                      self.secret_acl_ref)

    def test_should_get_secret_acl_using_stripped_uuid(self):
        bad_href = "http://badsite.com/secrets/" + self.secret_uuid
        self.test_should_get_secret_acl(bad_href)

    def test_should_get_secret_acl_with_extra_trailing_slashes(self):
        self.responses.get(requests_mock.ANY,
                           json=self.get_acl_response_data())
        # check if trailing slashes are corrected in get call.
        self.manager.get(entity_ref=self.secret_ref + '///')
        self.assertEqual(self.secret_acl_ref,
                         self.responses.last_request.url)

    def test_should_get_container_acl(self, entity_ref=None):
        entity_ref = entity_ref or self.container_ref
        self.responses.get(self.container_acl_ref,
                           json=self.get_acl_response_data())

        api_resp = self.manager.get(entity_ref=entity_ref)
        self.assertEqual(self.container_acl_ref,
                         self.responses.last_request.url)
        self.assertFalse(api_resp.get('read').project_access)
        self.assertEqual('read', api_resp.get('read').operation_type)
        self.assertIn(api_resp.get('read').acl_ref_relative,
                      self.container_acl_ref)

    def test_should_get_container_acl_using_stripped_uuid(self):
        bad_href = "http://badsite.com/containers/" + self.container_uuid
        self.test_should_get_container_acl(bad_href)

    def test_should_get_container_acl_with_trailing_slashes(self):
        self.responses.get(requests_mock.ANY,
                           json=self.get_acl_response_data())
        # check if trailing slashes are corrected in get call.
        self.manager.get(entity_ref=self.container_ref + '///')
        self.assertEqual(self.container_acl_ref,
                         self.responses.last_request.url)

    def test_should_fail_get_no_href(self):
        self.assertRaises(ValueError, self.manager.get, None)

    def test_should_fail_get_invalid_uri(self):
        # secret_acl URI expected and not secret URI
        self.assertRaises(ValueError, self.manager.get, self.secret_acl_ref)

        self.assertRaises(ValueError, self.manager.get,
                          self.endpoint + '/containers/consumers')

    def test_should_create_secret_acl(self):
        entity = self.manager.create(entity_ref=self.secret_ref + '///',
                                     users=self.users1, project_access=True)
        self.assertIsInstance(entity, acls.SecretACL)

        read_acl = entity.read
        # entity ref is kept same as provided input.
        self.assertEqual(self.secret_ref + '///', read_acl.entity_ref)
        self.assertTrue(read_acl.project_access)
        self.assertEqual(self.users1, read_acl.users)
        self.assertEqual(acls.DEFAULT_OPERATION_TYPE, read_acl.operation_type)
        # acl ref removes extra trailing slashes if there
        self.assertIn(self.secret_ref, read_acl.acl_ref,
                      'ACL ref has additional /acl')
        self.assertIsNone(read_acl.created)
        self.assertIsNone(read_acl.updated)

        read_acl_via_get = entity.get('read')
        self.assertEqual(read_acl, read_acl_via_get)

    def test_should_create_acl_with_users(self, entity_ref=None):
        entity_ref = entity_ref or self.container_ref
        entity = self.manager.create(entity_ref=entity_ref + '///',
                                     users=self.users2, project_access=False)
        self.assertIsInstance(entity, acls.ContainerACL)
        # entity ref is kept same as provided input.
        self.assertEqual(entity_ref + '///', entity.entity_ref)

        read_acl = entity.read
        self.assertFalse(read_acl.project_access)
        self.assertEqual(self.users2, read_acl.users)
        self.assertEqual(acls.DEFAULT_OPERATION_TYPE, read_acl.operation_type)
        # acl ref removes extra trailing slashes if there
        self.assertIn(entity_ref, read_acl.acl_ref,
                      'ACL ref has additional /acl')
        self.assertIn(read_acl.acl_ref_relative, self.container_acl_ref)

    def test_should_create_acl_with_users_stripped_uuid(self):
        bad_href = "http://badsite.com/containers/" + self.container_uuid
        self.test_should_create_acl_with_users(bad_href)

    def test_should_create_acl_with_no_users(self):
        entity = self.manager.create(entity_ref=self.container_ref, users=[])
        read_acl = entity.read
        self.assertEqual([], read_acl.users)
        self.assertEqual(acls.DEFAULT_OPERATION_TYPE, read_acl.operation_type)
        self.assertIsNone(read_acl.project_access)

        read_acl_via_get = entity.get('read')
        self.assertEqual(read_acl, read_acl_via_get)

    def test_create_no_acl_settings(self):

        entity = self.manager.create(entity_ref=self.container_ref)
        self.assertEqual([], entity.operation_acls)
        self.assertEqual(self.container_ref, entity.entity_ref)
        self.assertEqual(self.container_ref + '/acl', entity.acl_ref)

    def test_should_fail_create_invalid_uri(self):

        self.assertRaises(ValueError, self.manager.create,
                          self.endpoint + '/orders')
        self.assertRaises(ValueError, self.manager.create, None)


class WhenTestingACLEntity(ACLTestCase):

    def test_should_submit_acl_with_users_project_access_set(self, href=None):
        href = href or self.secret_ref
        data = {'acl_ref': self.secret_acl_ref}
        # register put acl URI with expected acl ref in response
        self.responses.put(self.secret_acl_ref, json=data)

        entity = self.manager.create(entity_ref=href + '///',
                                     users=self.users1, project_access=True)
        api_resp = entity.submit()
        self.assertEqual(self.secret_acl_ref, api_resp)
        self.assertEqual(self.secret_acl_ref,
                         self.responses.last_request.url)

    def test_should_submit_acl_with_users_project_access_stripped_uuid(self):
        bad_href = "http://badsite.com/secrets/" + self.secret_uuid
        self.test_should_submit_acl_with_users_project_access_set(bad_href)

    def test_should_submit_acl_with_project_access_set_but_no_users(self):
        data = {'acl_ref': self.secret_acl_ref}
        # register put acl URI with expected acl ref in response
        self.responses.put(self.secret_acl_ref, json=data)

        entity = self.manager.create(entity_ref=self.secret_ref,
                                     project_access=False)
        api_resp = entity.submit()
        self.assertEqual(self.secret_acl_ref, api_resp)
        self.assertEqual(self.secret_acl_ref,
                         self.responses.last_request.url)
        self.assertFalse(entity.read.project_access)
        self.assertEqual([], entity.get('read').users)

    def test_should_submit_acl_with_user_set_but_not_project_access(self):
        data = {'acl_ref': self.container_acl_ref}
        # register put acl URI with expected acl ref in response
        self.responses.put(self.container_acl_ref, json=data)

        entity = self.manager.create(entity_ref=self.container_ref,
                                     users=self.users2)
        api_resp = entity.submit()
        self.assertEqual(self.container_acl_ref, api_resp)
        self.assertEqual(self.container_acl_ref,
                         self.responses.last_request.url)
        self.assertEqual(self.users2, entity.read.users)
        self.assertIsNone(entity.get('read').project_access)

    def test_should_fail_submit_acl_invalid_secret_uri(self):
        data = {'acl_ref': self.secret_acl_ref}
        # register put acl URI with expected acl ref in response
        self.responses.put(self.secret_acl_ref, json=data)
        entity = self.manager.create(entity_ref=self.secret_acl_ref + '///',
                                     users=self.users1, project_access=True)
        # Submit checks provided URI is entity URI and not ACL URI.
        self.assertRaises(ValueError, entity.submit)

        entity = self.manager.create(entity_ref=self.secret_ref,
                                     users=self.users1, project_access=True)
        entity._entity_ref = None
        self.assertRaises(ValueError, entity.submit)

        entity = self.manager.create(entity_ref=self.secret_ref,
                                     users=self.users1, project_access=True)
        entity._entity_ref = self.container_ref  # expected secret uri here
        self.assertRaises(ValueError, entity.submit)

    def test_should_fail_submit_acl_invalid_container_uri(self):
        """Adding tests for container URI validation.

        Container URI validation is different from secret URI validation.
        That's why adding separate tests for code coverage.
        """

        data = {'acl_ref': self.container_acl_ref}
        # register put acl URI with expected acl ref in response
        self.responses.put(self.container_acl_ref, json=data)
        entity = self.manager.create(entity_ref=self.container_acl_ref + '///',
                                     users=self.users1, project_access=True)
        # Submit checks provided URI is entity URI and not ACL URI.
        self.assertRaises(ValueError, entity.submit)

        entity = self.manager.create(entity_ref=self.container_ref,
                                     users=self.users1, project_access=True)
        entity._entity_ref = None
        self.assertRaises(ValueError, entity.submit)

        entity = self.manager.create(entity_ref=self.container_ref,
                                     users=self.users1, project_access=True)
        entity._entity_ref = self.secret_ref  # expected container uri here
        self.assertRaises(ValueError, entity.submit)

    def test_should_fail_submit_acl_no_acl_data(self):
        data = {'acl_ref': self.secret_acl_ref}
        # register put acl URI with expected acl ref in response
        self.responses.put(self.secret_acl_ref, json=data)
        entity = self.manager.create(entity_ref=self.secret_ref + '///')
        # Submit checks that ACL setting data is there or not.
        self.assertRaises(ValueError, entity.submit)

    def test_should_fail_submit_acl_input_users_as_not_list(self):
        data = {'acl_ref': self.secret_acl_ref}
        # register put acl URI with expected acl ref in response
        self.responses.put(self.secret_acl_ref, json=data)
        entity = self.manager.create(entity_ref=self.secret_ref,
                                     users='u1')
        # Submit checks that input users are provided as list or not
        self.assertRaises(ValueError, entity.submit)

    def test_should_load_acls_data(self):
        self.responses.get(
            self.container_acl_ref, json=self.get_acl_response_data(
                users=self.users2, project_access=True))

        entity = self.manager.create(entity_ref=self.container_ref,
                                     users=self.users1)
        self.assertEqual(self.container_ref, entity.entity_ref)
        self.assertEqual(self.container_acl_ref, entity.acl_ref)

        entity.load_acls_data()

        self.assertEqual(self.users2, entity.read.users)
        self.assertTrue(entity.get('read').project_access)
        self.assertEqual(timeutils.parse_isotime(self.created),
                         entity.read.created)
        self.assertEqual(timeutils.parse_isotime(self.created),
                         entity.get('read').created)

        self.assertEqual(1, len(entity.operation_acls))
        self.assertEqual(self.container_acl_ref, entity.get('read').acl_ref)
        self.assertEqual(self.container_ref, entity.read.entity_ref)

    def test_should_add_operation_acl(self):
        entity = self.manager.create(entity_ref=self.secret_ref + '///',
                                     users=self.users1, project_access=True)
        self.assertIsInstance(entity, acls.SecretACL)

        entity.add_operation_acl(users=self.users2, project_access=False,
                                 operation_type='read')

        read_acl = entity.read
        # entity ref is kept same as provided input.
        self.assertEqual(self.secret_ref + '/acl', read_acl.acl_ref)
        self.assertFalse(read_acl.project_access)
        self.assertEqual(self.users2, read_acl.users)
        self.assertEqual(acls.DEFAULT_OPERATION_TYPE, read_acl.operation_type)

        entity.add_operation_acl(users=[], project_access=False,
                                 operation_type='dummy')
        dummy_acl = entity.get('dummy')
        self.assertFalse(dummy_acl.project_access)
        self.assertEqual([], dummy_acl.users)

    def test_acl_entity_properties(self):

        entity = self.manager.create(entity_ref=self.secret_ref,
                                     users=self.users2)
        self.assertEqual(self.secret_ref, entity.entity_ref)
        self.assertEqual(self.secret_acl_ref, entity.acl_ref)

        self.assertEqual(self.users2, entity.read.users)
        self.assertEqual(self.users2, entity.get('read').users)
        self.assertIsNone(entity.read.project_access)
        self.assertIsNone(entity.get('read').project_access)
        self.assertIsNone(entity.read.created)
        self.assertIsNone(entity.get('read').created)
        self.assertEqual('read', entity.read.operation_type)
        self.assertEqual('read', entity.get('read').operation_type)

        self.assertEqual(1, len(entity.operation_acls))
        self.assertEqual(self.secret_acl_ref, entity.read.acl_ref)
        self.assertEqual(self.secret_acl_ref, entity.get('read').acl_ref)
        self.assertEqual(self.secret_ref, entity.read.entity_ref)

        self.assertIsNone(entity.get('dummyOperation'))

        entity.read.users = ['u1']
        entity.read.project_access = False
        entity.read.operation_type = 'my_operation'
        self.assertFalse(entity.get('my_operation').project_access)
        self.assertEqual(['u1'], entity.get('my_operation').users)

        self.assertRaises(AttributeError, lambda x: x.dummy_operation, entity)

    def test_get_formatted_data(self):

        s_entity = acls.SecretACL(api=None,
                                  entity_ref=self.secret_ref,
                                  users=self.users1)

        data = s_entity.read._get_formatted_data()

        self.assertEqual(acls.DEFAULT_OPERATION_TYPE, data[0])
        self.assertIsNone(data[1])
        self.assertEqual(self.users1, data[2])
        self.assertIsNone(data[3])  # created
        self.assertIsNone(data[4])  # updated
        self.assertEqual(self.secret_acl_ref, data[5])

        c_entity = acls.ContainerACL(api=None,
                                     entity_ref=self.container_ref,
                                     users=self.users2, created=self.created)

        data = c_entity.get('read')._get_formatted_data()

        self.assertEqual(acls.DEFAULT_OPERATION_TYPE, data[0])
        self.assertIsNone(data[1])
        self.assertEqual(self.users2, data[2])
        self.assertEqual(timeutils.parse_isotime(self.created).isoformat(),
                         data[3])  # created
        self.assertIsNone(data[4])  # updated
        self.assertEqual(self.container_acl_ref, data[5])

    def test_should_secret_acl_remove(self, entity_ref=None):
        entity_ref = entity_ref or self.secret_ref
        self.responses.delete(self.secret_acl_ref)

        entity = self.manager.create(entity_ref=entity_ref,
                                     users=self.users2)

        api_resp = entity.remove()
        self.assertEqual(self.secret_acl_ref,
                         self.responses.last_request.url)
        self.assertIsNone(api_resp)

    def test_should_secret_acl_remove_uri_with_slashes(self):
        self.responses.delete(self.secret_acl_ref)

        # check if trailing slashes are corrected in delete call.
        entity = self.manager.create(entity_ref=self.secret_ref + '///',
                                     users=self.users2)
        entity.remove()
        self.assertEqual(self.secret_acl_ref,
                         self.responses.last_request.url)

        self.responses.delete(self.container_acl_ref)

    def test_should_secret_acl_remove_stripped_uuid(self):
        bad_href = "http://badsite.com/secrets/" + self.secret_uuid
        self.test_should_secret_acl_remove(bad_href)

    def test_should_container_acl_remove(self, entity_ref=None):
        entity_ref = entity_ref or self.container_ref
        self.responses.delete(self.container_acl_ref)

        entity = self.manager.create(entity_ref=entity_ref)
        entity.remove()
        self.assertEqual(self.container_acl_ref,
                         self.responses.last_request.url)

    def test_should_container_acl_remove_stripped_uuid(self):
        bad_href = "http://badsite.com/containers/" + self.container_uuid
        self.test_should_container_acl_remove(bad_href)

    def test_should_fail_acl_remove_invalid_uri(self):
        # secret_acl URI expected and not secret acl URI
        entity = self.manager.create(entity_ref=self.secret_acl_ref)
        self.assertRaises(ValueError, entity.remove)

        entity = self.manager.create(entity_ref=self.container_acl_ref)
        self.assertRaises(ValueError, entity.remove)

        entity = self.manager.create(entity_ref=self.container_ref +
                                     '/consumers')
        self.assertRaises(ValueError, entity.remove)

        # check to make sure UUID is passed in
        entity = self.manager.create(entity_ref=self.endpoint + '/secrets' +
                                     '/consumers')
        self.assertRaises(ValueError, entity.remove)

    def test_should_per_operation_acl_remove(self):
        self.responses.get(self.secret_acl_ref,
                           json=self.get_acl_response_data(users=self.users2,
                                                           project_access=True)
                           )
        self.responses.delete(self.secret_acl_ref)

        entity = self.manager.create(entity_ref=self.secret_ref,
                                     users=self.users2)

        api_resp = entity.read.remove()
        self.assertEqual(self.secret_acl_ref,
                         self.responses.last_request.url)
        self.assertIsNone(api_resp)
        self.assertEqual(0, len(entity.operation_acls))

        # now try case where there are 2 operation acls defined
        # and one operation specific acl is removed. In that case,
        # entity.submit() is called instead of remove to update rest of entity

        acl_data = self.get_acl_response_data(users=self.users2,
                                              project_access=True)

        data = self.get_acl_response_data(users=self.users1,
                                          operation_type='write',
                                          project_access=False)
        acl_data['write'] = data['write']

        self.responses.get(self.secret_acl_ref, json=acl_data)
        self.responses.put(self.secret_acl_ref, json={})
        # check if trailing slashes are corrected in delete call.
        entity = self.manager.create(entity_ref=self.secret_ref,
                                     users=self.users2)
        entity.read.remove()
        self.assertEqual(self.secret_acl_ref,
                         self.responses.last_request.url)
        self.assertEqual(1, len(entity.operation_acls))
        self.assertEqual('write', entity.operation_acls[0].operation_type)
        self.assertEqual(self.users1, entity.operation_acls[0].users)
