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

import logging

import base_behaviors


class ContainerBehaviors(base_behaviors.BaseBehaviors):

    def __init__(self):
        super(ContainerBehaviors, self).__init__()
        self.LOG = logging.getLogger(type(self).__name__)
        self.container_hrefs_to_delete = []

    def delete_container(self, container_href):
        """Delete a container

        :param container_href the href to the container to delete
        """
        argv = ['secret', 'container', 'delete']
        self.add_auth_and_endpoint(argv)
        argv.extend([container_href])

        stdout, stderr = self.issue_barbican_command(argv)

        self.container_hrefs_to_delete.remove(container_href)

    def create_container(self, secret_hrefs=[]):
        """Create a container

        :param secret_hrefs A list of existing secrets

        :return: the href to the newly created container
        """
        argv = ['secret', 'container', 'create']
        self.add_auth_and_endpoint(argv)
        for secret_href in secret_hrefs:
            argv.extend(['--secret', secret_href])

        stdout, stderr = self.issue_barbican_command(argv)

        container_data = self._prettytable_to_dict(stdout)

        container_href = container_data['Container href']
        self.container_hrefs_to_delete.append(container_href)
        return container_href

    def get_container(self, container_href):
        """Get a container

        :param: the href to a container
        :return dict of container values, or an empty dict if the container
        is not found.
        """
        argv = ['secret', 'container', 'get']
        self.add_auth_and_endpoint(argv)
        argv.extend([container_href])

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        container_data = self._prettytable_to_dict(stdout)
        return container_data

    def list_containers(self):
        """List containers

        :return: a list of containers
        """
        argv = ['secret', 'container', 'list']

        self.add_auth_and_endpoint(argv)
        stdout, stderr = self.issue_barbican_command(argv)
        container_list = self._prettytable_to_list(stdout)
        return container_list

    def delete_all_created_containers(self):
        """Delete all containers that we created"""
        # Create a copy of the list -- otherwise delete_container will remove
        # items from the list as we are iterating over it
        containers_to_delete = list(self.container_hrefs_to_delete)
        for href in containers_to_delete:
            self.delete_container(href)
