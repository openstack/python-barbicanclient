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

from functionaltests.cli.base import CmdLineTestCase
from functionaltests.cli.v1.behaviors import container_behaviors
from functionaltests.cli.v1.behaviors import secret_behaviors
from testtools import testcase


class ContainerTestCase(CmdLineTestCase):

    def setUp(self):
        super(ContainerTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors()
        self.container_behaviors = container_behaviors.ContainerBehaviors()

    def tearDown(self):
        super(ContainerTestCase, self).tearDown()
        self.secret_behaviors.delete_all_created_secrets()
        self.container_behaviors.delete_all_created_containers()

    @testcase.attr('positive')
    def test_container_create(self):
        secret_href = self.secret_behaviors.store_secret()
        container_href = self.container_behaviors.create_container(
            secret_hrefs=[secret_href])
        self.assertIsNotNone(container_href)

        container = self.container_behaviors.get_container(container_href)
        self.assertEqual(container_href, container['Container href'])

    @testcase.attr('positive')
    def test_container_list(self):
        containers_to_create = 10
        for _ in range(containers_to_create):
            secret_href = self.secret_behaviors.store_secret()
            self.container_behaviors.create_container(
                secret_hrefs=[secret_href])
        container_list = self.container_behaviors.list_containers()
        self.assertGreaterEqual(len(container_list), containers_to_create)

    @testcase.attr('positive')
    def test_container_delete(self):
        secret_href = self.secret_behaviors.store_secret()
        container_href = self.container_behaviors.create_container(
            secret_hrefs=[secret_href])
        self.container_behaviors.delete_container(container_href)

        container = self.container_behaviors.get_container(container_href)
        self.assertFalse(container)

    @testcase.attr('positive')
    def test_container_get(self):
        secret_href = self.secret_behaviors.store_secret()
        container_href = self.container_behaviors.create_container(
            secret_hrefs=[secret_href])
        container = self.container_behaviors.get_container(container_href)
        self.assertIsNotNone(container)
