"""
Copyright 2015 IBM

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


class CleanUp(object):

    def __init__(self, barbicanclient):
        self.created_entities = {
            'secret': [],
            'container': [],
            'acl': [],
            'order': []
        }

        self.barbicanclient = barbicanclient

    def delete_all_entities(self):
        """Helper method to delete all entities used for testing"""
        self._delete_all_acls()
        self._delete_all_containers()
        self._delete_all_orders()
        self._delete_all_secrets()

    def add_entity(self, entity):
        """Stores an entity in Barbican

        used for testing and keeps track of entity for removal after
        tests are running

        """
        entity_type = str(type(entity)).lower()
        if 'acl' in entity_type:
            entity_ref = entity.submit()
            entity_type = 'acl'
        elif 'secret' in entity_type:
            entity_ref = entity.store()
            entity_type = 'secret'
        elif 'container' in entity_type:
            entity_ref = entity.store()
            entity_type = 'container'
        else:
            entity_ref = entity.submit()
            entity_type = 'order'

        self.created_entities[entity_type].append(entity_ref)
        return entity_ref

    def delete_entity(self, entity):
        """Deletes an entity from Barbican

        Used for testing. Individually deletes an entity.

        """
        entity_type = entity.lower()
        if 'acl' in entity_type:
            entity_type = 'acl'
        elif 'secret' in entity_type:
            entity_type = 'secret'
        elif 'container' in entity_type:
            entity_type = 'container'
        else:
            entity_type = 'order'

        self.created_entities[entity_type].remove(entity)

    def _delete_all_containers(self):
        """Helper method to delete all containers used for testing"""
        for container_ref in self.created_entities['container']:
            self.barbicanclient.containers.delete(container_ref)

    def _delete_all_secrets(self):
        """Helper method to delete all secrets used for testing"""
        for secret_ref in self.created_entities['secret']:
            self.barbicanclient.secrets.delete(secret_ref, True)

    def _delete_all_acls(self):
        """Helper method to delete all acls used for testing"""
        for acl_ref in self.created_entities['acl']:
            entity_ref = acl_ref.replace("/acl", "")
            blank_acl_entity = self.barbicanclient.acls.create(
                entity_ref=entity_ref)
            blank_acl_entity.remove()

    def _delete_all_orders(self):
        """Helper method to delete all orders and secrets used for testing"""
        for order_ref in self.created_entities['order']:
            order = self.barbicanclient.orders.get(order_ref)
            if order.secret_ref:
                self.barbicanclient.secrets.delete(order.secret_ref)
            # see if containers are supported
            container_attr_exists = getattr(order, "container_ref", None)
            if container_attr_exists and order.container_ref:
                self.barbicanclient.containers.delete(order.container_ref)

            self.barbicanclient.orders.delete(order_ref)
