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

from functionaltests.cli.base import CmdLineTestCase
from functionaltests.cli.v1.behaviors import acl_behaviors
from functionaltests.cli.v1.behaviors import container_behaviors
from functionaltests.cli.v1.behaviors import secret_behaviors
from functionaltests import utils
from testtools import testcase

ARGS_TYPE = {'short_arg_false': [False],
             'short_arg_true': [True]}


@utils.parameterized_test_case
class ACLTestCase(CmdLineTestCase):

    def setUp(self):
        super(ACLTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors()
        self.container_behaviors = container_behaviors.ContainerBehaviors()
        self.acl_behaviors = acl_behaviors.ACLBehaviors()

    def tearDown(self):
        super(ACLTestCase, self).tearDown()
        self.acl_behaviors.delete_all_created_acls()
        self.container_behaviors.delete_all_created_containers()
        self.secret_behaviors.delete_all_created_secrets()

    @utils.parameterized_dataset(ARGS_TYPE)
    @testcase.attr('positive')
    def test_acl_submit(self, use_short_arg):
        secret_ref = self.secret_behaviors.store_secret()
        container_ref = self.container_behaviors.create_container(
            secret_hrefs=[secret_ref])

        data = self.acl_behaviors.acl_submit(entity_ref=secret_ref,
                                             users=['u1', 'u2'],
                                             use_short_arg=use_short_arg)
        self.assertIsNotNone(data)
        self.assertIn('u1', data['Users'])
        self.assertIn('u2', data['Users'])
        self.assertEqual('True', data['Project Access'])
        self.assertIn(secret_ref, data['Secret ACL Ref'])

        data = self.acl_behaviors.acl_submit(entity_ref=container_ref,
                                             users=['u2', 'u3'],
                                             use_short_arg=use_short_arg)
        self.assertIsNotNone(data)
        self.assertIn('u3', data['Users'])
        self.assertNotIn('u1', data['Users'])
        self.assertEqual('True', data['Project Access'])
        self.assertIn(container_ref, data['Container ACL Ref'])

    @utils.parameterized_dataset(ARGS_TYPE)
    @testcase.attr('positive')
    def test_acl_submit_for_overwriting_existing_users(self, use_short_arg):
        secret_ref = self.secret_behaviors.store_secret()
        container_ref = self.container_behaviors.create_container(
            secret_hrefs=[secret_ref])

        data = self.acl_behaviors.acl_submit(entity_ref=secret_ref,
                                             users=['u1', 'u2'],
                                             project_access=False,
                                             use_short_arg=use_short_arg)
        self.assertIsNotNone(data)
        self.assertIn('u1', data['Users'])
        self.assertIn('u2', data['Users'])
        self.assertEqual('False', data['Project Access'])
        self.assertIn(secret_ref, data['Secret ACL Ref'])

        data = self.acl_behaviors.acl_submit(entity_ref=container_ref,
                                             users=[],
                                             project_access=True,
                                             use_short_arg=use_short_arg)
        self.assertIsNotNone(data)
        self.assertNotIn('u1', data['Users'])
        self.assertNotIn('u2', data['Users'])
        self.assertEqual('True', data['Project Access'])
        self.assertIn(container_ref, data['Container ACL Ref'])

    @utils.parameterized_dataset(ARGS_TYPE)
    @testcase.attr('positive')
    def test_acl_add(self, use_short_arg):
        secret_ref = self.secret_behaviors.store_secret()

        data = self.acl_behaviors.acl_submit(entity_ref=secret_ref,
                                             project_access=False,
                                             users=['u1', 'u2'])
        self.assertIsNotNone(data)
        self.assertEqual('False', data['Project Access'])

        acls = self.acl_behaviors.acl_add(entity_ref=secret_ref,
                                          users=['u2', 'u3'],
                                          use_short_arg=use_short_arg)
        data = acls[0]  # get 'read' operation ACL data
        self.assertIsNotNone(data)
        self.assertIn('u1', data['Users'])
        self.assertIn('u3', data['Users'])
        self.assertEqual('False', data['Project Access'])
        self.assertIn(secret_ref, data['Secret ACL Ref'])

        # make sure there is no change in existing users with blank users add
        acls = self.acl_behaviors.acl_add(entity_ref=secret_ref,
                                          users=[], project_access=False,
                                          use_short_arg=use_short_arg)
        data = acls[0]  # get 'read' operation ACL data
        self.assertIsNotNone(data)
        self.assertIn('u1', data['Users'])
        self.assertIn('u2', data['Users'])
        self.assertIn('u3', data['Users'])

        acls = self.acl_behaviors.acl_add(entity_ref=secret_ref,
                                          users=None, project_access=True,
                                          use_short_arg=use_short_arg)
        data = acls[0]  # get 'read' operation ACL data
        self.assertIsNotNone(data)
        self.assertIn('u2', data['Users'])
        self.assertEqual('True', data['Project Access'])

    @utils.parameterized_dataset(ARGS_TYPE)
    @testcase.attr('positive')
    def test_acl_remove(self, use_short_arg):
        secret_ref = self.secret_behaviors.store_secret()
        container_ref = self.container_behaviors.create_container(
            secret_hrefs=[secret_ref])

        data = self.acl_behaviors.acl_submit(entity_ref=container_ref,
                                             project_access=False,
                                             users=['u1', 'u2'])
        self.assertIsNotNone(data)
        self.assertEqual('False', data['Project Access'])

        acls = self.acl_behaviors.acl_remove(entity_ref=container_ref,
                                             users=['u2', 'u3'],
                                             use_short_arg=use_short_arg)
        data = acls[0]  # get 'read' operation ACL data
        self.assertIsNotNone(data)
        self.assertIn('u1', data['Users'])
        self.assertNotIn('u2', data['Users'])
        self.assertEqual('False', data['Project Access'])
        self.assertIn(container_ref, data['Container ACL Ref'])

        # make sure there is no change in existing users with blank users
        # remove
        acls = self.acl_behaviors.acl_remove(entity_ref=container_ref,
                                             users=[], project_access=False,
                                             use_short_arg=use_short_arg)
        data = acls[0]  # get 'read' operation ACL data
        self.assertIsNotNone(data)
        self.assertIn('u1', data['Users'])
        self.assertEqual('False', data['Project Access'])

    @testcase.attr('positive')
    def test_acl_get(self):
        secret_ref = self.secret_behaviors.store_secret()
        container_ref = self.container_behaviors.create_container(
            secret_hrefs=[secret_ref])

        data = self.acl_behaviors.acl_submit(entity_ref=secret_ref,
                                             users=['u1', 'u2'])
        self.assertIsNotNone(data)

        data = self.acl_behaviors.acl_get(entity_ref=secret_ref)

        self.assertIn('u2', data['Users'])
        self.assertEqual('True', data['Project Access'])
        self.assertEqual(secret_ref + "/acl", data['Secret ACL Ref'])

        data = self.acl_behaviors.acl_get(entity_ref=secret_ref + "///")

        self.assertIn('u2', data['Users'])
        self.assertEqual('True', data['Project Access'])
        self.assertEqual(secret_ref + "/acl", data['Secret ACL Ref'])

        data = self.acl_behaviors.acl_submit(entity_ref=container_ref,
                                             project_access=False,
                                             users=['u4', 'u5'])
        self.assertIsNotNone(data)

        data = self.acl_behaviors.acl_get(entity_ref=container_ref)

        self.assertIn('u4', data['Users'])
        self.assertIn('u5', data['Users'])
        self.assertEqual('False', data['Project Access'])
        self.assertEqual(container_ref + '/acl', data['Container ACL Ref'])

    @testcase.attr('positive')
    def test_acl_delete(self):
        secret_ref = self.secret_behaviors.store_secret()

        data = self.acl_behaviors.acl_submit(entity_ref=secret_ref,
                                             users=['u1', 'u2'])
        self.assertIsNotNone(data)

        self.acl_behaviors.acl_delete(entity_ref=secret_ref)

        data = self.acl_behaviors.acl_get(entity_ref=secret_ref)

        self.assertEqual('[]', data['Users'])
        self.assertEqual('True', data['Project Access'])
        self.assertEqual(secret_ref + "/acl", data['Secret ACL Ref'])

        # deleting again should be okay as secret or container always has
        # default ACL settings
        self.acl_behaviors.acl_delete(entity_ref=secret_ref + '////')
        data = self.acl_behaviors.acl_get(entity_ref=secret_ref)

        self.assertEqual('[]', data['Users'])
        self.assertEqual('True', data['Project Access'])

    @testcase.attr('negative')
    def test_acl_entity_ref_input_with_acl_uri(self):
        secret_ref = self.secret_behaviors.store_secret()
        container_ref = self.container_behaviors.create_container(
            secret_hrefs=[secret_ref])

        data = self.acl_behaviors.acl_submit(entity_ref=secret_ref,
                                             users=['u1', 'u2'])
        self.assertIsNotNone(data)

        err = self.acl_behaviors.acl_delete(entity_ref=container_ref + '/acl')
        # above container ACL ref is passed instead of expected container_ref
        self.assertIn('Container ACL URI', err)

        err = self.acl_behaviors.acl_delete(entity_ref=secret_ref + '/acl')
        # above secret ACL ref is passed instead of expected secret_ref
        self.assertIn('Secret ACL URI', err)
