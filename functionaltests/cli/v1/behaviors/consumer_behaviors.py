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

import logging

from functionaltests.cli.v1.behaviors import base_behaviors


class ConsumerBehaviors(base_behaviors.BaseBehaviors):

    def __init__(self):
        super(ConsumerBehaviors, self).__init__()
        self.LOG = logging.getLogger(type(self).__name__)

    def register_consumer(self, secret_href, service, resource_type,
                          resource_id):
        argv = ['secret', 'consumer', 'create']
        self.add_auth_and_endpoint(argv)

        argv.extend(['--service-type-name', service])
        argv.extend(['--resource-type', resource_type])
        argv.extend(['--resource-id', resource_id])
        argv.extend([secret_href])

        stdout, stderr = self.issue_barbican_command(argv)

    def remove_consumer(self, secret_href, service, resource_type,
                        resource_id):
        argv = ['secret', 'consumer', 'delete']
        self.add_auth_and_endpoint(argv)

        argv.extend(['--service-type-name', service])
        argv.extend(['--resource-type', resource_type])
        argv.extend(['--resource-id', resource_id])
        argv.extend([secret_href])

        stdout, stderr = self.issue_barbican_command(argv)

    def list_consumers(self, secret_href):
        argv = ['secret', 'consumer', 'list']
        self.add_auth_and_endpoint(argv)

        argv.extend([secret_href])

        stdout, stderr = self.issue_barbican_command(argv)

        if len(stderr) > 0 or stdout == '\n':
            return []
        else:
            consumers = self._prettytable_to_list(stdout)
            return consumers
