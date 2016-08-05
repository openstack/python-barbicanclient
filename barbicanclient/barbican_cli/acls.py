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
"""
Command-line interface sub-commands related to ACLs.
"""
from cliff import command
from cliff import lister

from barbicanclient import acls


class ArgMixin(object):
    "Mixin class for CLI arguments and validation"

    def add_ref_arg(self, parser):
        parser.add_argument('URI',
                            help='The URI reference for the secret or '
                            'container.')

    def add_per_acl_args(self, parser):
        parser.add_argument('--user', '-u',
                            action='append', default=None, nargs='?',
                            dest='users',
                            help='Keystone userid(s) for ACL.')

        group = parser.add_mutually_exclusive_group()
        group.add_argument('--project-access',
                           dest='project_access',
                           action='store_true',
                           default=None,
                           help='Flag to enable project access behavior.')
        group.add_argument('--no-project-access',
                           dest='project_access',
                           action='store_false',
                           help='Flag to disable project access behavior.')

        parser.add_argument('--operation-type', '-o',
                            default=acls.DEFAULT_OPERATION_TYPE,
                            dest='operation_type', choices=['read'],
                            help='Type of Barbican operation ACL is set for')

    def create_blank_acl_entity_from_uri(self, acl_manager, args):
        """Validates URI argument and creates blank ACL entity"""

        entity = acl_manager.create(args.URI)
        entity.validate_input_ref()
        return entity

    def create_acl_entity_from_args(self, acl_manager, args):
        blank_entity = self.create_blank_acl_entity_from_uri(acl_manager, args)

        users = args.users
        if users is None:
            users = []
        else:
            users = [user for user in users if user is not None]
        entity = acl_manager.create(
            entity_ref=blank_entity.entity_ref, users=users,
            project_access=args.project_access,
            operation_type=args.operation_type)
        return entity

    def get_acls_as_lister(self, acl_entity):
        """Gets per operation ACL data in expected format for lister command"""

        map(lambda acl: setattr(acl, 'columns', acl_entity.columns),
            acl_entity.operation_acls)

        return acls.ACLFormatter._list_objects(acl_entity.operation_acls)


class DeleteACLs(command.Command, ArgMixin):
    """Delete ACLs for a secret or container as identified by its href."""

    def get_parser(self, prog_name):
        parser = super(DeleteACLs, self).get_parser(prog_name)
        self.add_ref_arg(parser)
        return parser

    def take_action(self, args):
        """Deletes a secret or container ACL settings from Barbican.

        This action removes all of defined ACL settings for a secret or
        container in Barbican.
        """
        blank_entity = self.create_blank_acl_entity_from_uri(
            self.app.client_manager.key_manager.acls, args)
        blank_entity.remove()


class GetACLs(lister.Lister, ArgMixin):
    """Retrieve ACLs for a secret or container by providing its href."""

    def get_parser(self, prog_name):
        parser = super(GetACLs, self).get_parser(prog_name)
        self.add_ref_arg(parser)
        return parser

    def take_action(self, args):
        """Retrieves a secret or container ACL settings from Barbican.

        This action provides list of all ACL settings for a secret or container
        in Barbican.

        :returns: List of objects for valid entity_ref
        :rtype: :class:`barbicanclient.acls.SecretACL` or
            :class:`barbicanclient.acls.ContainerACL`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        blank_entity = self.create_blank_acl_entity_from_uri(
            self.app.client_manager.key_manager.acls, args)
        acl_entity = self.app.client_manager.key_manager.acls.get(
            blank_entity.entity_ref)
        return self.get_acls_as_lister(acl_entity)


class SubmitACL(lister.Lister, ArgMixin):
    """Submit ACL on a secret or container as identified by its href."""

    def get_parser(self, prog_name):
        parser = super(SubmitACL, self).get_parser(prog_name)
        self.add_ref_arg(parser)
        self.add_per_acl_args(parser)
        return parser

    def take_action(self, args):
        """Submit complete secret or container ACL settings to Barbican

        This action replaces existing ACL setting on server with provided
        inputs.

        :returns: List of objects for valid entity_ref
        :rtype: :class:`barbicanclient.acls.SecretACL` or
            :class:`barbicanclient.acls.ContainerACL`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        entity = self.create_acl_entity_from_args(
            self.app.client_manager.key_manager.acls, args)

        entity.submit()
        entity.load_acls_data()  # read ACL settings from server
        return self.get_acls_as_lister(entity)


class AddACLUsers(lister.Lister, ArgMixin):
    """Add ACL users to a secret or container as identified by its href."""

    def get_parser(self, prog_name):
        parser = super(AddACLUsers, self).get_parser(prog_name)
        self.add_ref_arg(parser)
        self.add_per_acl_args(parser)
        return parser

    def take_action(self, args):
        """Add users to a secret or a container ACL defined in Barbican

        Provided users are added to existing ACL users if there. If input users
        is None or empty list, no change is made in existing ACL users list.
        If input project_access flag is None, then no change is made in
        existing project access behavior.

        :returns: List of objects for valid entity_ref
        :rtype: :class:`barbicanclient.acls.SecretACL` or
            :class:`barbicanclient.acls.ContainerACL`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """

        input_entity = self.create_acl_entity_from_args(
            self.app.client_manager.key_manager.acls, args)

        server_entity = self.app.client_manager.key_manager.acls.get(
            input_entity.entity_ref)

        for input_acl in input_entity.operation_acls:
            server_acl = server_entity.get(input_acl.operation_type)
            if server_acl:
                if input_acl.project_access is not None:
                    server_acl.project_access = input_acl.project_access
                # if input data has users, add it to existing users list
                if input_acl.users is not None:
                    server_acl.users.extend(input_acl.users)
            # provided input operation_type does not exist in server entity
            else:
                server_entity.add_operation_acl(
                    users=input_acl.users,
                    project_access=input_acl.project_access,
                    operation_type=input_acl.operation_type)

        server_entity.submit()  # apply changes to server
        server_entity.load_acls_data()
        return self.get_acls_as_lister(server_entity)


class RemoveACLUsers(lister.Lister, ArgMixin):
    """Remove ACL users from a secret or container as identified by its href.

    """

    def get_parser(self, prog_name):
        parser = super(RemoveACLUsers, self).get_parser(prog_name)
        self.add_ref_arg(parser)
        self.add_per_acl_args(parser)
        return parser

    def take_action(self, args):

        """Remove users from a secret or a container ACL defined in Barbican

        Provided users are removed from existing ACL users if there. If any of
        input users are not part of ACL users, they are simply ignored.
        If input project_access flag is None, then no change is made in
        existing project access behavior.

        :returns: List of objects for valid entity_ref
        :rtype: :class:`barbicanclient.acls.SecretACL` or
            :class:`barbicanclient.acls.ContainerACL`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        input_entity = self.create_acl_entity_from_args(
            self.app.client_manager.key_manager.acls, args)

        server_entity = self.app.client_manager.key_manager.acls.get(
            input_entity.entity_ref)

        for input_acl in input_entity.operation_acls:
            server_acl = server_entity.get(input_acl.operation_type)
            if server_acl:
                if input_acl.project_access is not None:
                    server_acl.project_access = input_acl.project_access
                # if input data has users, then remove matching one
                # from server acl users
                if input_acl.users is not None:
                    acl_users = server_acl.users
                    acl_users = set(acl_users).difference(input_acl.users)
                    del server_acl.users[:]
                    # Python sets are not JSON serializable.
                    # Cast acl_users to a list.
                    server_acl.users = list(acl_users)

        server_entity.submit()  # apply changes to server
        server_entity.load_acls_data()

        return self.get_acls_as_lister(server_entity)
