# Copyright 2022 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from functionaltests.cli.base import CmdLineTestCase
from functionaltests.cli.v1.behaviors.consumer_behaviors import (
    ConsumerBehaviors)
from functionaltests.cli.v1.behaviors.secret_behaviors import SecretBehaviors
from functionaltests import utils
from testtools import testcase


@utils.parameterized_test_case
class ConsumerTestCase(CmdLineTestCase):

    def setUp(self):
        super(ConsumerTestCase, self).setUp()
        self.consumer_behaviors = ConsumerBehaviors()
        self.secret_behaviors = SecretBehaviors()

    def tearDown(self):
        super(ConsumerTestCase, self).tearDown()
        self.secret_behaviors.delete_all_created_secrets()

    def _create_secret(self):
        secret_href = self.secret_behaviors.store_secret()
        secret = self.secret_behaviors.get_secret(secret_href)
        return secret['Secret href']

    def _create_secret_with_consumer(self, consumer):
        secret_href = self._create_secret()
        self.consumer_behaviors.register_consumer(
            secret_href, consumer["service"], consumer["resource_type"],
            consumer["resource_id"])
        return secret_href

    def _register_consumer(self, secret_href, consumer):
        self.consumer_behaviors.register_consumer(
            secret_href, consumer["service"], consumer["resource_type"],
            consumer["resource_id"])

    @testcase.attr('positive')
    def test_register_consumer_on_empty_secret(self):
        consumer = {
            'service': 'service', 'resource_type': 'type',
            'resource_id': 'id', 'created': 'created'
        }
        secret_href = self._create_secret_with_consumer(consumer)

        secret = self.consumer_behaviors.list_consumers(secret_href)
        # Because "created" is non-deterministic, we need to assign
        # its value before running the loop below.
        secret[0]['Created'] = consumer['created']
        # The CLI's output is slighted different in terms of headers.
        # So, we have to rename their keys to the consumer dictionary's keys.
        for (k1, v1), (k2, v2) in zip(list(secret[0].items()),
                                      consumer.items()):
            secret[0][k2] = secret[0].pop(k1)
        self.assertDictEqual(consumer, secret[0])

    @testcase.attr('positive')
    def test_register_duplicated_service_name_consumer(self):
        consumer = {
            'service': 'service', 'resource_type': 'type', 'resource_id': 'id'
        }
        secret_href = self._create_secret_with_consumer(consumer)
        second_consumer = {
            'service': 'service', 'resource_type': 'type2',
            'resource_id': 'id2'
        }
        self._register_consumer(secret_href, second_consumer)
        self._register_consumer(secret_href, second_consumer)
        consumers_list = self.consumer_behaviors.list_consumers(secret_href)
        self.assertEqual(2, len(consumers_list))

    @testcase.attr('positive')
    def test_register_duplicated_resource_type_consumer(self):
        consumer = {
            'service': 'service', 'resource_type': 'type',
            'resource_id': 'id'
        }
        secret_href = self._create_secret_with_consumer(consumer)
        second_consumer = {
            'service': 'service2', 'resource_type': 'type',
            'resource_id': 'id2'
        }
        self._register_consumer(secret_href, second_consumer)
        consumers_list = self.consumer_behaviors.list_consumers(secret_href)
        self.assertEqual(2, len(consumers_list))

    @testcase.attr('positive')
    def test_register_duplicated_resource_id_consumer(self):
        consumer = {
            'service': 'service', 'resource_type': 'type', 'resource_id': 'id'
        }
        secret_href = self._create_secret_with_consumer(consumer)
        second_consumer = {
            'service': 'service2', 'resource_type': 'type2',
            'resource_id': 'id'
        }
        self._register_consumer(secret_href, second_consumer)
        consumers_list = self.consumer_behaviors.list_consumers(secret_href)
        self.assertEqual(2, len(consumers_list))

    @testcase.attr('positive')
    def test_remove_consumer(self):
        consumer = {
            'service': 'service', 'resource_type': 'type',
            'resource_id': 'id'
        }
        secret_href = self._create_secret_with_consumer(consumer)

        self.consumer_behaviors.remove_consumer(
            secret_href, consumer["service"], consumer["resource_type"],
            consumer["resource_id"])

        consumers = self.consumer_behaviors.list_consumers(secret_href)
        self.assertEqual(0, len(consumers))

    @testcase.attr('positive')
    def test_list_consumer_secret_with_multiple_consumers(self):
        first_consumer = {
            'service': 'service1', 'resource_type': 'type1',
            'resource_id': 'id1'}
        secret_href = self._create_secret_with_consumer(first_consumer)

        second_consumer = {
            'service': 'service2', 'resource_type': 'type2',
            'resource_id': 'id2'}
        self._register_consumer(secret_href, second_consumer)

        consumers = self.consumer_behaviors.list_consumers(secret_href)
        self.assertEqual(2, len(consumers))
