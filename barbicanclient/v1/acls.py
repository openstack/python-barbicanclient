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

import logging

from oslo_utils.timeutils import parse_isotime

from barbicanclient import base
from barbicanclient import formatter


LOG = logging.getLogger(__name__)

DEFAULT_OPERATION_TYPE = 'read'

VALID_ACL_OPERATIONS = ['read', 'write', 'delete', 'list']


class ACLFormatter(formatter.EntityFormatter):

    columns = ("Operation Type",
               "Project Access",
               "Users",
               "Created",
               "Updated",
               )

    def _get_formatted_data(self):
        created = self.created.isoformat() if self.created else None
        updated = self.updated.isoformat() if self.updated else None
        data = (self.operation_type,
                self.project_access,
                self.users,
                created,
                updated,
                self.acl_ref,
                )
        return data


class _PerOperationACL(ACLFormatter):

    def __init__(self, parent_acl, entity_ref=None, users=None,
                 project_access=None, operation_type=None,
                 created=None, updated=None):
        """Per Operation ACL data instance for secret or container.

        This class not to be instantiated outside of this module.

        :param parent_acl: acl entity to this per operation data belongs to
        :param str entity_ref: Full HATEOAS reference to a secret or container
        :param users: List of Keystone userid(s) to be used for ACL.
        :type users: List or None
        :param bool project_access: Flag indicating project access behavior
        :param str operation_type: Type indicating which class of Barbican
            operations this ACL is defined for e.g. 'read' operations
        :param str created: Time string indicating ACL create timestamp. This
            is populated only when populating data from api response. Not
            needed in client input.
        :param str updated: Time string indicating ACL last update timestamp.
            This is populated only when populating data from api response. Not
            needed in client input.
        """
        self._parent_acl = parent_acl
        self._entity_ref = entity_ref
        self._users = users if users else list()
        self._project_access = project_access
        self._operation_type = operation_type
        self._created = parse_isotime(created) if created else None
        self._updated = parse_isotime(updated) if updated else None

    @property
    def acl_ref(self):
        return ACL.get_acl_ref_from_entity_ref(self.entity_ref)

    @property
    def acl_ref_relative(self):
        return self._parent_acl.acl_ref_relative

    @property
    def entity_ref(self):
        return self._entity_ref

    @property
    def entity_uuid(self):
        return self._parent_acl.entity_uuid

    @property
    def project_access(self):
        """Flag indicating project access behavior is enabled or not"""
        return self._project_access

    @property
    def users(self):
        """List of users for this ACL setting"""
        return self._users

    @property
    def operation_type(self):
        """Type indicating class of Barbican operations for this ACL"""
        return self._operation_type

    @property
    def created(self):
        return self._created

    @property
    def updated(self):
        return self._updated

    @operation_type.setter
    def operation_type(self, value):
        self._operation_type = value

    @project_access.setter
    def project_access(self, value):
        self._project_access = value

    @users.setter
    def users(self, value):
        self._users = value

    def remove(self):
        """Remove operation specific setting defined for a secret or container

        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        """
        LOG.debug('Removing {0} operation specific ACL for href: {1}'
                  .format(self.operation_type, self.acl_ref))

        self._parent_acl.load_acls_data()
        acl_entity = self._parent_acl

        # Find matching operation specific acl entry and remove from list
        per_op_acl = acl_entity.get(self.operation_type)
        if per_op_acl:
            acl_entity.operation_acls.remove(per_op_acl)

            # after above operation specific acl removal, check if there are
            # any remaining acls. If yes, then submit updates to server.
            # If not, then remove/delete acls from server.
            if acl_entity.operation_acls:
                acl_entity.submit()
            else:
                acl_entity.remove()

    def _validate_users_type(self):
        if self.users and not (type(self.users) is list or
                               type(self.users) is set):
            raise ValueError('Users value is expected to be provided'
                             ' as list/set.')


class ACL(object):

    _resource_name = 'acl'

    def __init__(self, api, entity_ref, users=None, project_access=None,
                 operation_type=DEFAULT_OPERATION_TYPE, created=None,
                 updated=None):
        """Base ACL entity instance for secret or container.

        Provide ACL data arguments to set ACL setting for given operation_type.

        To add ACL setting for other operation types, use `add_operation_acl`
        method.

        :param api: client instance reference
        :param str entity_ref: Full HATEOAS reference to a secret or container
        :param users: List of Keystone userid(s) to be used for ACL.
        :type users: str List or None
        :param bool project_access: Flag indicating project access behavior
        :param str operation_type: Type indicating which class of Barbican
            operations this ACL is defined for e.g. 'read' operations
        :param str created: Time string indicating ACL create timestamp. This
            is populated only when populating data from api response. Not
            needed in client input.
        :param str updated: Time string indicating ACL last update timestamp.
            This is populated only when populating data from api response. Not
            needed in client input.
        """

        self._api = api
        self._entity_ref = entity_ref
        self._operation_acls = []

        # create per operation ACL data entity only when client has set users
        # or project_access flag.
        if users is not None or project_access is not None:
            acl = _PerOperationACL(parent_acl=self, entity_ref=entity_ref,
                                   users=users, project_access=project_access,
                                   operation_type=operation_type,
                                   created=created, updated=updated)
            self._operation_acls.append(acl)

    @property
    def entity_ref(self):
        """Entity URI reference."""
        return self._entity_ref

    @property
    def entity_uuid(self):
        """Entity UUID"""
        return str(base.validate_ref_and_return_uuid(
            self._entity_ref, self._acl_type))

    @property
    def operation_acls(self):
        """List of operation specific ACL settings."""
        return self._operation_acls

    @property
    def acl_ref(self):
        return ACL.get_acl_ref_from_entity_ref(self.entity_ref)

    @property
    def acl_ref_relative(self):
        return ACL.get_acl_ref_from_entity_ref_relative(
            self.entity_uuid, self._parent_entity_path)

    def add_operation_acl(self, users=None, project_access=None,
                          operation_type=None, created=None,
                          updated=None,):
        """Add ACL settings to entity for specific operation type.

        If matching operation_type ACL already exists, then it replaces it with
        new PerOperationACL object using provided inputs. Otherwise it appends
        new PerOperationACL object to existing per operation ACL list.

        This just adds to local entity and have not yet applied these changes
        to server.

        :param users: List of Keystone userid(s) to be used in ACL.
        :type users: List or None
        :param bool project_access: Flag indicating project access behavior
        :param str operation_type: Type indicating which class of Barbican
            operations this ACL is defined for e.g. 'read' operations
        :param str created: Time string indicating ACL create timestamp. This
            is populated only when populating data from api response. Not
            needed in client input.
        :param str updated: Time string indicating ACL last update timestamp.
            This is populated only when populating data from api response. Not
            needed in client input.
        """
        new_acl = _PerOperationACL(parent_acl=self, entity_ref=self.entity_ref,
                                   users=users, project_access=project_access,
                                   operation_type=operation_type,
                                   created=created, updated=updated)

        for i, acl in enumerate(self._operation_acls):
            if acl.operation_type == operation_type:
                # replace with new ACL setting
                self._operation_acls[i] = new_acl
                break
        else:
            self._operation_acls.append(new_acl)

    def _get_operation_acl(self, operation_type):
        return next((acl for acl in self._operation_acls
                     if acl.operation_type == operation_type), None)

    def get(self, operation_type):
        """Get operation specific ACL instance.

        :param str operation_type: Type indicating which operation's ACL
            setting is needed.
        """
        return self._get_operation_acl(operation_type)

    def __getattr__(self, name):
        if name in VALID_ACL_OPERATIONS:
            return self._get_operation_acl(name)
        else:
            raise AttributeError(name)

    def submit(self):
        """Submits ACLs for a secret or a container defined in server

        In existing ACL case, this overwrites the existing ACL setting with
        provided inputs. If input users are None or empty list, this will
        remove existing ACL users if there. If input project_access flag is
        None, then default project access behavior is enabled.

        :returns: str acl_ref: Full HATEOAS reference to a secret or container
            ACL.
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Submitting complete {0} ACL for href: {1}'
                  .format(self.acl_type, self.entity_ref))
        if not self.operation_acls:
            raise ValueError('ACL data for {0} is not provided.'.
                             format(self._acl_type))

        self.validate_input_ref()

        acl_dict = {}

        for per_op_acl in self.operation_acls:
            per_op_acl._validate_users_type()
            op_type = per_op_acl.operation_type
            acl_data = {}
            if per_op_acl.project_access is not None:
                acl_data['project-access'] = per_op_acl.project_access
            if per_op_acl.users is not None:
                acl_data['users'] = per_op_acl.users
            acl_dict[op_type] = acl_data

        response = self._api.put(self.acl_ref_relative, json=acl_dict)

        return response.json().get('acl_ref')

    def remove(self):
        """Remove Barbican ACLs setting defined for a secret or container

        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        """
        self.validate_input_ref()
        LOG.debug('Removing ACL for {0} for href: {1}'
                  .format(self.acl_type, self.entity_ref))
        self._api.delete(self.acl_ref_relative)

    def load_acls_data(self):
        """Loads ACL entity from Barbican server using its acl_ref

        Clears the existing list of per operation ACL settings if there.
        Populates current ACL entity with ACL settings received from Barbican
        server.

        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """

        response = self._api.get(self.acl_ref_relative)

        del self.operation_acls[:]  # clearing list for all of its references
        for op_type in response:
            acl_dict = response.get(op_type)
            proj_access = acl_dict.get('project-access')
            users = acl_dict.get('users')
            created = acl_dict.get('created')
            updated = acl_dict.get('updated')
            self.add_operation_acl(operation_type=op_type,
                                   project_access=proj_access,
                                   users=users, created=created,
                                   updated=updated)

    def validate_input_ref(self):
        res_title = self._acl_type.title()
        if not self.entity_ref:
            raise ValueError('{0} href is required.'.format(res_title))
        if self._parent_entity_path in self.entity_ref:
            if '/acl' in self.entity_ref:
                raise ValueError('{0} ACL URI provided. Expecting {0} URI.'
                                 .format(res_title))
            ref_type = self._acl_type
        else:
            raise ValueError('{0} URI is not specified.'.format(res_title))

        base.validate_ref_and_return_uuid(self.entity_ref, ref_type)
        return ref_type

    @staticmethod
    def get_acl_ref_from_entity_ref(entity_ref):
        # Utility for converting entity ref to acl ref
        if entity_ref:
            entity_ref = entity_ref.rstrip('/')
            return '{0}/{1}'.format(entity_ref, ACL._resource_name)

    @staticmethod
    def get_acl_ref_from_entity_ref_relative(entity_ref, entity_type):
        # Utility for converting entity ref to acl ref
        if entity_ref:
            entity_ref = entity_ref.rstrip('/')
            return '{0}/{1}/{2}'.format(entity_type, entity_ref,
                                        ACL._resource_name)

    @staticmethod
    def identify_ref_type(entity_ref):
        # Utility for identifying ACL type from given entity URI.
        if not entity_ref:
            raise ValueError('Secret or container href is required.')
        if '/secrets' in entity_ref:
            ref_type = 'secret'
        elif '/containers' in entity_ref:
            ref_type = 'container'
        else:
            raise ValueError('Secret or container URI is not specified.')

        return ref_type


class SecretACL(ACL):
    """ACL entity for a secret"""

    columns = ACLFormatter.columns + ("Secret ACL Ref",)
    _acl_type = 'secret'
    _parent_entity_path = '/secrets'

    @property
    def acl_type(self):
        return self._acl_type


class ContainerACL(ACL):
    """ACL entity for a container"""

    columns = ACLFormatter.columns + ("Container ACL Ref",)
    _acl_type = 'container'
    _parent_entity_path = '/containers'

    @property
    def acl_type(self):
        return self._acl_type


class ACLManager(base.BaseEntityManager):
    """Entity Manager for Secret or Container ACL entities"""

    acl_class_map = {
        'secret': SecretACL,
        'container': ContainerACL
    }

    def __init__(self, api):
        super(ACLManager, self).__init__(api, ACL._resource_name)

    def create(self, entity_ref=None, users=None, project_access=None,
               operation_type=DEFAULT_OPERATION_TYPE):
        """Factory method for creating `ACL` entity.

        `ACL` object returned by this method have not yet been
        stored in Barbican.

        Input entity_ref is used to determine whether
        ACL object type needs to be :class:`barbicanclient.acls.SecretACL`
        or  :class:`barbicanclient.acls.ContainerACL`.

        :param str entity_ref: Full HATEOAS reference to a secret or container
        :param users: List of Keystone userid(s) to be used in ACL.
        :type users: List or None
        :param bool project_access: Flag indicating project access behavior
        :param str operation_type: Type indicating which class of Barbican
            operations this ACL is defined for e.g. 'read' operations
        :returns: ACL object instance
        :rtype: :class:`barbicanclient.v1.acls.SecretACL` or
            :class:`barbicanclient.v1.acls.ContainerACL`
        """
        entity_type = ACL.identify_ref_type(entity_ref)

        entity_class = ACLManager.acl_class_map.get(entity_type)
        # entity_class cannot be None as entity_ref is already validated above
        return entity_class(api=self._api, entity_ref=entity_ref, users=users,
                            project_access=project_access,
                            operation_type=operation_type)

    def get(self, entity_ref):
        """Retrieve existing ACLs for a secret or container found in Barbican

        :param str entity_ref: Full HATEOAS reference to a secret or container.
        :returns: ACL entity object instance
        :rtype: :class:`barbicanclient.v1.acls.SecretACL` or
            :class:`barbicanclient.v1.acls.ContainerACL`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        """
        entity = self._validate_acl_ref(entity_ref)
        LOG.debug('Getting ACL for {0} href: {1}'
                  .format(entity.acl_type, entity.acl_ref))
        entity.load_acls_data()
        return entity

    def _validate_acl_ref(self, entity_ref):
        if entity_ref is None:
            raise ValueError('Expected secret or container URI is not '
                             'specified.')

        entity_ref = entity_ref.rstrip('/')
        entity_type = ACL.identify_ref_type(entity_ref)

        entity_class = ACLManager.acl_class_map.get(entity_type)
        acl_entity = entity_class(api=self._api, entity_ref=entity_ref)
        acl_entity.validate_input_ref()
        return acl_entity
