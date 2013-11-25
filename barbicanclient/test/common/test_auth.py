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

import mock
import unittest2 as unittest

from barbicanclient.common import auth


class WhenTestingKeystoneAuthentication(unittest.TestCase):

    def setUp(self):
        self.keystone_client = mock.MagicMock()

        self.auth_url = 'https://www.yada.com'
        self.username = 'user'
        self.password = 'pw'
        self.tenant_id = '1234'

        self.keystone_auth = auth.KeystoneAuthV2(auth_url=self.auth_url,
                                                 username=self.username,
                                                 password=self.password,
                                                 tenant_id=self.tenant_id,
                                                 keystone=
                                                 self.keystone_client)

    def test_endpoint_username_password_tenant_are_required(self):
        with self.assertRaises(ValueError):
            keystone = auth.KeystoneAuthV2()

    def test_get_barbican_url(self):
        barbican_url = 'https://www.barbican.com'
        self.keystone_auth._barbican_url = barbican_url
        self.assertEquals(barbican_url, self.keystone_auth.barbican_url)
