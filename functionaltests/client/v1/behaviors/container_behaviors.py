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


class ContainerBehaviors(base_behaviors.BaseBehaviors):

    def create_generic_container(self, data, secrets=None):
        """Creates a generic container object

        :param data: Data used to create object
        :param secrets: Optional paramter to include a dictionary of secrets
            to override the default secrets data.
        :return: A generic container object
        """
        if secrets:
            data['secrets'] = secrets
        return self.client.containers.create(**data)

    def create_rsa_container(self, data, disable_passphrase=False):
        """Creates RSA container object

        :param data: Data used to create object
        :param disable_passphrase: Option to disable the passphrase on an RSA
            container
        :return: RSA container object
        """
        if disable_passphrase:
            data['private_key_passphrase'] = None

        return self.client.containers.create_rsa(**data)

    def create_certificate_container(self, data):
        """Creates a certificate container object

        :param data: Data used to create object
        :return: Certificate container object
        """
        return self.client.containers.create_certificate(**data)

    def store_container(self, container):
        """Create generic container from the data in a client container object

        :param container: A container object
        :return: A container ref
        """

        resp = container.store()
        container_ref = str(resp)

        if container_ref:
            self.created_entities.append(container_ref)
        return resp

    def get_container(self, container_ref):
        """Handles getting a single container

        :param container_ref: Reference to the container to be retrieved
        :return: A container object.
        """

        return self.client.containers.get(container_ref)

    def get_containers(self, limit=10, offset=0):
        """Handles getting a list of containers.

        :param limit: limits number of returned containers
        :param offset: represents how many records to skip before retrieving
            the list
        :return: A list of barbican client container objects.
        """
        return self.client.containers.list(limit=limit, offset=offset)

    def delete_container(self, container_ref, expected_fail=False):
        """Handles deleting a containers.

        :param container_ref: Reference of the container to be deleted
        :param expected_fail: If there is a negative test, this should be
            marked true if you are trying to delete a container that does
            not exist.
        :return: Response of the delete.
        """
        resp = self.client.containers.delete(container_ref)

        if not expected_fail:
            self.created_entities.remove(container_ref)

        return resp

    def delete_all_created_containers(self):
        """Delete all of the containers that we have created."""
        containers_to_delete = [container for container
                                in self.created_entities]

        for container_ref in containers_to_delete:
            self.delete_container(container_ref)
