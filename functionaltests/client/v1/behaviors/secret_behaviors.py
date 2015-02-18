"""
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from functionaltests.client.v1.behaviors import base_behaviors


class SecretBehaviors(base_behaviors.BaseBehaviors):

    def create_secret(self, data):
        """Creates a Barbican client secret object.

        This does not store the object in the database.

        :param data: Data for creation of the barbican object.
        :return: Barbican client secret object
        """
        return self.client.secrets.create(**data)

    def store_secret(self, secret):
        """Stores a secret object in the barbican datastore.

        Creating a secret in the client only creates the Secret object.
        The secret is not saved to the database until a store is called.

        :param secret: A barbican client secret object
        :return: The ref to the created secret
        """
        resp = secret.store()

        if resp:
            self.created_entities.append(resp)

        return resp

    def get_secret(self, secret_ref, payload_content_type=None):
        """Retrieves a secret and its payload.

            :param secret_ref: A secret reference
            :param payload_content_type: The secrets content type
            :return: A barbican secret object with all meta and payload
                information
        """
        resp = self.client.secrets.get(
            secret_ref,
            payload_content_type=payload_content_type)

        return resp

    def get_secrets(self, limit=10, offset=0):
        """Handles getting a list of secrets.

        :param limit: limits number of returned secrets
        :param offset: represents how many records to skip before retrieving
                       the list
        :return: A list of secret objects
        """
        resp = self.client.secrets.list(limit=limit, offset=offset)

        return resp

    def delete_secret(self, secret_ref, expected_fail=False):
        """Delete a secret.

        :param secret_ref: HATEOS ref of the secret to be deleted
        :param expected_fail: If test is expected to fail the deletion
        :return: On failure will return a string
        """
        resp = self.client.secrets.delete(secret_ref)

        if not expected_fail:
            self.created_entities.remove(secret_ref)

        return resp

    def delete_all_created_secrets(self):
        """Delete all of the secrets that we have created."""
        slist = []

        for entity in self.created_entities:
            slist.append(entity)

        for secret_ref in slist:
            self.delete_secret(secret_ref)
