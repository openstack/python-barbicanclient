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

from functionaltests.cli.v1.behaviors import base_behaviors


class SecretBehaviors(base_behaviors.BaseBehaviors):

    def __init__(self):
        super(SecretBehaviors, self).__init__()
        self.LOG = logging.getLogger(type(self).__name__)
        self.secret_hrefs_to_delete = []

    def update_secret(self,
                      secret_href,
                      payload):
        """Update a secret

        :param secret_href the href to the secret to update.
        :param payload the payload to put into the secret.
        :param payload_content_type the payload content type.
        """
        argv = ['secret', 'update']
        self.add_auth_and_endpoint(argv)
        argv.extend([secret_href])
        argv.extend([payload])

        stdout, stderr = self.issue_barbican_command(argv)

    def delete_secret(self, secret_href):
        """Delete a secret

        :param secret_href the href to the secret to delete
        """
        argv = ['secret', 'delete', '--force']
        self.add_auth_and_endpoint(argv)
        argv.extend([secret_href])

        stdout, stderr = self.issue_barbican_command(argv)

        self.secret_hrefs_to_delete.remove(secret_href)

    def store_secret(self, payload=b"Payload for testing", store_argv=[]):
        """Store (aka create) a secret

        The store_argv parameter allows additional command line parameters for
        the store operation to be specified. This can be used to specify -a for
        algorithm as an example.

        :param payload The payload to use when storing the secret
        :param store_argv The store command line parameters

        :return: the href to the newly created secret
        """
        argv = ['secret', 'store']
        self.add_auth_and_endpoint(argv)

        if payload is not None and not isinstance(payload, str):
            # Payload shouldn't be bytes but string on Python3
            payload = payload.decode('utf-8')

        argv.extend(['--payload', payload])
        argv.extend(store_argv)

        stdout, stderr = self.issue_barbican_command(argv)

        secret_data = self._prettytable_to_dict(stdout)

        secret_href = secret_data['Secret href']
        self.secret_hrefs_to_delete.append(secret_href)
        return secret_href

    def store_secret_file(self, filename="/tmp/storesecret", store_argv=[]):
        """Store (aka create) a secret from file

        The store_argv parameter allows additional command line parameters for
        the store operation to be specified. This can be used to specify -a for
        algorithm as an example.

        :param payload The payload to use when storing the secret
        :param store_argv The store command line parameters

        :return: the href to the newly created secret
        """
        argv = ['secret', 'store']
        self.add_auth_and_endpoint(argv)
        argv.extend(['--file', filename])
        argv.extend(store_argv)

        stdout, stderr = self.issue_barbican_command(argv)

        secret_data = self._prettytable_to_dict(stdout)

        secret_href = secret_data['Secret href']
        self.secret_hrefs_to_delete.append(secret_href)
        return secret_href

    def get_secret(self, secret_href):
        """Get a secret

        :param: the href to a secret
        :return: dict of secret values, or an empty dict if the secret
        is not found.
        """
        argv = ['secret', 'get']
        self.add_auth_and_endpoint(argv)
        argv.extend([secret_href])

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        secret_data = self._prettytable_to_dict(stdout)
        return secret_data

    def get_secret_payload(self, secret_href, raw=False):
        """Get a secret

        :param: the href to a secret
        :param raw if True then add "-f value" to get raw payload (ie not
        within a PrettyTable).  If False then omit -f.
        :return: string representing the secret payload.
        """
        argv = ['secret', 'get']
        self.add_auth_and_endpoint(argv)
        argv.extend([secret_href])
        argv.extend(['--payload'])
        if raw:
            argv.extend(['-f', 'value'])

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        if raw:
            secret = stdout.rstrip()
        else:
            secret_data = self._prettytable_to_dict(stdout)
            secret = secret_data['Payload']

        return secret

    def get_secret_file(self, secret_href, filename='/tmp/getsecret'):
        """Get a secret and store in a file

        :param: the href to a secret
        :param filename: name of file to store secret in
        :return string representing the file name.
        """
        argv = ['secret', 'get']
        self.add_auth_and_endpoint(argv)
        argv.extend([secret_href])
        argv.extend(['--file', filename])

        stdout, stderr = self.issue_barbican_command(argv)

        if '4xx Client error: Not Found' in stderr:
            return {}

        return filename

    def list_secrets(self):
        """List secrets

        :return: a list of secrets
        """
        argv = ['secret', 'list']

        self.add_auth_and_endpoint(argv)
        stdout, stderr = self.issue_barbican_command(argv)

        secret_list = self._prettytable_to_list(stdout)
        return secret_list

    def delete_all_created_secrets(self):
        """Delete all secrets that we created"""
        # Create a copy of the list -- otherwise delete_secret will remove
        # items from the list as we are iterating over it
        secrets_to_delete = list(self.secret_hrefs_to_delete)
        for href in secrets_to_delete:
            self.delete_secret(href)

    def read_secret_test_file(self, filename='/tmp/getsecret'):
        """Read payload from file used in testing

        :param filename: name of file to write
        :return contents of the file
        """
        with open(filename, "rb") as myfile:
            data = myfile.read()
        return data.decode('utf-8')

    def write_secret_test_file(self, filename='/tmp/storesecret',
                               payload="Payload for testing"):
        """Write payload to file for use in testing

        :param filename: name of file to write
        :param payload: data to store
        :return
        """
        myfile = open(filename, "wb")
        myfile.write(payload.encode('utf-8'))
        myfile.close()
        return
