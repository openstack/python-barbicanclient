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

import base_behaviors


class ACLBehaviors(base_behaviors.BaseBehaviors):

    _args_map_list = {'users': ['--user', '-u'],
                      'operation_type': ['--operation-type', '-o']
                      }

    def __init__(self):
        super(ACLBehaviors, self).__init__()
        self.LOG = logging.getLogger(type(self).__name__)
        self.acl_entity_set = set()

    def _add_ref_arg(self, argv, entity_ref):
        argv.extend([entity_ref])
        return argv

    def _add_per_acl_args(self, argv, users=[], project_access=None,
                          operation_type=None, use_short_arg=False):
        index = 1 if use_short_arg else 0

        if users is not None:
            if users:
                for user in users:
                    argv.extend([self._args_map_list['users'][index], user])
            else:  # empty list case
                argv.extend([self._args_map_list['users'][index]])
        if project_access is not None:
            if project_access:
                argv.extend(['--project-access'])
            else:
                argv.extend(['--no-project-access'])
        if operation_type and operation_type is not 'read':
            argv.extend([self._args_map_list['operation_type'][index],
                         operation_type])

        return argv

    def acl_delete(self, entity_ref):
        """Delete a secret or container acl

        :param entity_ref Reference to secret or container entity
        :return If error returns stderr string otherwise returns None.
        """
        argv = ['acl', 'delete']
        self.add_auth_and_endpoint(argv)
        self._add_ref_arg(argv, entity_ref)

        _, stderr = self.issue_barbican_command(argv)

        self.acl_entity_set.discard(entity_ref)

        if stderr:
            return stderr

    def acl_get(self, entity_ref):
        """Get a 'read' ACL setting for a secret or a container.

        :param entity_ref Reference to secret or container entity
        :return dict of 'read' operation ACL settings if found otherwise empty
            dict in case of error.
        """
        argv = ['acl', 'get']
        self.add_auth_and_endpoint(argv)
        self._add_ref_arg(argv, entity_ref)

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        acl_list = self._prettytable_to_list(stdout)
        return acl_list[0]  # return first ACL which is for 'read' op type

    def acl_submit(self, entity_ref, users=None,
                   project_access=None, use_short_arg=False,
                   operation_type='read'):
        """Submits a secret or container ACL

        :param entity_ref Reference to secret or container entity
        :param users List of users for ACL
        :param project_access: Flag to pass for project access behavior
        :param use_short_arg: Flag to indicate if use short arguments in cli.
            Default is False
        :param operation_type: ACL operation type. Default is 'read' as
            Barbican currently supports only that type of operation.
        :return dict of 'read' operation ACL settings if found otherwise empty
            dict in case of error.
        """
        argv = ['acl', 'submit']
        self.add_auth_and_endpoint(argv)
        self._add_per_acl_args(argv, users=users,
                               project_access=project_access,
                               use_short_arg=use_short_arg,
                               operation_type=operation_type)
        self._add_ref_arg(argv, entity_ref)

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        acl_list = self._prettytable_to_list(stdout)
        self.acl_entity_set.add(entity_ref)

        return acl_list[0]  # return first ACL which is for 'read' op type

    def acl_add(self, entity_ref, users=None,
                project_access=None, use_short_arg=False,
                operation_type='read'):
        """Add to a secret or container ACL

        :param entity_ref Reference to secret or container entity
        :param users List of users to be added in ACL
        :param project_access: Flag to pass for project access behavior
        :param use_short_arg: Flag to indicate if use short arguments in cli.
            Default is False
        :param operation_type: ACL operation type. Default is 'read' as
            Barbican currently supports only that type of operation.
        :return dict of 'read' operation ACL settings if found otherwise empty
            dict in case of error.
        """
        argv = ['acl', 'user', 'add']
        self.add_auth_and_endpoint(argv)

        self._add_per_acl_args(argv, users=users,
                               project_access=project_access,
                               use_short_arg=use_short_arg,
                               operation_type=operation_type)
        self._add_ref_arg(argv, entity_ref)

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        self.acl_entity_set.add(entity_ref)

        acl_list = self._prettytable_to_list(stdout)
        return acl_list

    def acl_remove(self, entity_ref, users=None,
                   project_access=None, use_short_arg=False,
                   operation_type='read'):
        """Remove users from a secret or container ACL

        :param entity_ref Reference to secret or container entity
        :param users List of users to be removed from ACL
        :param project_access: Flag to pass for project access behavior
        :param use_short_arg: Flag to indicate if use short arguments in cli.
            Default is False
        :param operation_type: ACL operation type. Default is 'read' as
            Barbican currently supports only that type of operation.
        :return dict of 'read' operation ACL settings if found otherwise empty
            dict in case of error.
        """
        argv = ['acl', 'user', 'remove']
        self.add_auth_and_endpoint(argv)

        self._add_per_acl_args(argv, users=users,
                               project_access=project_access,
                               use_short_arg=use_short_arg,
                               operation_type=operation_type)
        self._add_ref_arg(argv, entity_ref)

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        acl_list = self._prettytable_to_list(stdout)
        return acl_list

    def delete_all_created_acls(self):
        """Delete all ACLs that we created"""
        entities_to_delete = [entry for entry in self.acl_entity_set]
        for entity_ref in entities_to_delete:
            self.acl_delete(entity_ref)
