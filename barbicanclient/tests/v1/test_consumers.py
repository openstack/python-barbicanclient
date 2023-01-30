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

from barbicanclient import client
from barbicanclient.tests import test_client
from barbicanclient.tests.utils import mock_delete_secret_for_responses
from barbicanclient.tests.utils import mock_get_secret_for_client
from barbicanclient.tests.v1.test_secrets import SecretData
from barbicanclient.v1 import secrets

from oslo_serialization import jsonutils


class WhenTestingConsumers(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('secrets')

        self.secret = SecretData()

        self.client_v1_0 = client.Client(
            endpoint=self.endpoint, project_id=self.project_id,
            microversion='1.0')

        self.manager = self.client.secrets
        self.manager_v1_0 = self.client_v1_0.secrets

        self.consumers_post_resource = self.entity_href + '/consumers/'
        self.consumers_delete_resource = self.entity_href + '/consumers'

    def test_register_consumer_fails_with_lower_microversion(self):
        self.assertRaises(
            NotImplementedError, self.manager_v1_0.register_consumer,
            self.entity_href, self.secret.consumer.get('service'),
            self.secret.consumer.get('resource_type'),
            self.secret.consumer.get('resource_id'))

    def _register_consumer(self):
        data = self.secret.get_dict(
            self.entity_href, consumers=[self.secret.consumer])
        self.responses.post(self.entity_href + '/consumers/', json=data)
        return self.manager.register_consumer(
            self.entity_href, self.secret.consumer.get('service'),
            self.secret.consumer.get('resource_type'),
            self.secret.consumer.get('resource_id'))

    def test_should_register_consumer_with_correct_microversion(self):
        self._register_consumer()

    def test_should_register_consumer_and_return_secret(self):
        self.assertIsInstance(self._register_consumer(), secrets.Secret)

    def test_should_register_consumer_with_correct_secret_href(self):
        secret = self._register_consumer()
        self.assertEqual(self.entity_href, secret.secret_ref)

    def test_should_register_consumer_with_correct_url(self):
        self._register_consumer()
        self.assertEqual(
            self.consumers_post_resource, self.responses.last_request.url)

    def test_should_register_consumer_with_consumer(self):
        secret = self._register_consumer()
        self.assertEqual([self.secret.consumer], secret.consumers)

    def test_remove_consumer_fails_with_lower_microversion(self):
        self.assertRaises(
            NotImplementedError, self.manager_v1_0.remove_consumer,
            self.entity_href, self.secret.consumer.get('service'),
            self.secret.consumer.get('resource_type'),
            self.secret.consumer.get('resource_id'))

    def _remove_consumer(self):
        self.responses.delete(self.entity_href + '/consumers', status_code=204)
        self.manager.remove_consumer(
            self.entity_href, self.secret.consumer.get('service'),
            self.secret.consumer.get('resource_type'),
            self.secret.consumer.get('resource_id'))

    def test_should_remove_consumer_with_correct_microversion(self):
        self._remove_consumer()

    def test_should_remove_consumer_with_correct_url(self):
        self._remove_consumer()
        self.assertEqual(
            self.consumers_delete_resource, self.responses.last_request.url)

    def test_should_remove_consumer_with_correct_consumer(self):
        self._remove_consumer()
        self.assertEqual(
            self.consumers_delete_resource, self.responses.last_request.url)

        body = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.secret.consumer, body)

    def _delete_from_manager(self, secret_ref, force=False, consumers=[]):
        mock_get_secret_for_client(self.client, consumers=consumers)
        mock_delete_secret_for_responses(self.responses, self.entity_href)
        self.manager.delete(secret_ref=secret_ref, force=force)

    def _delete_from_manager_with_consumers(self, secret_ref, force=False):
        consumers = [{'service': 'service_test',
                      'resource_type': 'type_test',
                      'resource_id': 'id_test'}]

        self._delete_from_manager(secret_ref, force=force, consumers=consumers)

    def test_delete_from_manager_fails_with_consumers_without_force(self):
        self.assertRaises(
            ValueError,
            self._delete_from_manager_with_consumers, self.entity_href,
            force=False)

    def test_should_delete_from_manager_with_consumers_and_force(self):
        self._delete_from_manager_with_consumers(self.entity_href, force=True)

    def test_should_delete_from_manager_without_consumers_and_force(self):
        self._delete_from_manager(self.entity_href, force=True)

    def _list_consumers(self, secret_ref, consumers=[]):
        mock_get_secret_for_client(self.client, consumers)
        return self.manager.list_consumers(secret_ref)

    def test_list_consumers_from_secret_without_consumers(self):
        consumer_list = self._list_consumers(self.entity_href)
        self.assertTrue(len(consumer_list) == 0)

    def test_list_consumers_from_secret_with_consumers(self):
        consumers = [{'service': 'service_test1',
                      'resource_type': 'type_test1',
                      'resource_id': 'id_test1'},
                     {'service': 'service_test2',
                      'resource_type': 'type_test2',
                      'resource_id': 'id_test2'}]
        consumer_list = self._list_consumers(self.entity_href, consumers)

        for elem in range(len(consumers)):
            self.assertTrue(
                consumer_list[elem].service ==
                consumers[elem]['service'])
            self.assertTrue(
                consumer_list[elem].resource_type ==
                consumers[elem]['resource_type'])
            self.assertTrue(
                consumer_list[elem].resource_id ==
                consumers[elem]['resource_id'])

    def test_should_fail_list_consumers_invalid_secret(self):
        self.assertRaises(ValueError, self.manager.list_consumers,
                          **{'secret_ref': '12345'})
