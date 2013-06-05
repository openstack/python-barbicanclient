# Copyright (c) 2013 Rackspace, Inc.
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

import unittest

from mock import MagicMock
from barbicanclient.client import Connection


def suite():
    suite = unittest.TestSuite()

    suite.addTest(WhenTestingConnection())

    return suite


class WhenTestingConnection(unittest.TestCase):

    def setUp(self):
        self.auth_endpoint = 'https://keystone.com/v2'
        self.user = 'user'
        self.key = 'key'
        self.tenant = 'tenant'
        self.endpoint = 'http://localhost:9311/v1/'
        self.auth_token = 'token'

        self.authenticate = MagicMock()
        self.authenticate.return_value = (self.endpoint, self.auth_token)
        self.connection = Connection(self.auth_endpoint, self.user, self.key,
                                     self.tenant, self.authenticate,
                                     token=self.auth_token)

    def test_should_connect_with_token(self):
        self.assertFalse(self.authenticate.called)

    def test_should_connect_without_token(self):
        self.connection = Connection(self.auth_endpoint,
                                     self.user,
                                     self.key,
                                     self.tenant,
                                     self.authenticate,
                                     endpoint=self.endpoint
                                     )
        self.authenticate\
            .assert_called_once_with(self.auth_endpoint,
                                     self.user,
                                     self.key,
                                     self.tenant,
                                     endpoint=self.endpoint,
                                     cacert=None
                                     )
        self.assertEqual(self.auth_token, self.connection.auth_token)
        self.assertEqual(self.auth_endpoint, self.connection._auth_endpoint)
        self.assertEqual(self.user, self.connection._user)
        self.assertEqual(self.key, self.connection._key)
        self.assertEqual(self.tenant, self.connection._tenant)
        self.assertEqual(self.endpoint, self.connection._endpoint)

    def test_should_create_secret(self):
        pass

if __name__ == '__main__':
    unittest.main()
