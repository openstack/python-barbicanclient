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
import json

from mock import MagicMock

from barbicanclient.openstack.common.timeutils import parse_isotime
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
        self.request = MagicMock()
        self.request.return_value.content = json.dumps(
            {
                "secret_ref": "http://localhost:9311/None/secrets"
                              "/8502cea9-9d35-46d7-96f5-80e43905e4c5"
            }
        )
        self.request.return_value.headers = {
            'content-length': '92',
            'content-type': 'application/json; charset=utf-8',
            'location': 'http://localhost:9311/None/'
                        'secrets/8502cea9-9d35-46d7-96f5-80e43905e4c5',
            'x-openstack-request-id':
            'req-6c19d09e-1167-445c-b435-d6b0818b59b9'
        }
        self.request.return_value.ok = True
        self.connection = Connection(self.auth_endpoint, self.user, self.key,
                                     self.tenant, token=self.auth_token,
                                     authenticate=self.authenticate,
                                     request=self.request)

    def test_should_connect_with_token(self):
        self.assertFalse(self.authenticate.called)

    def test_should_connect_without_token(self):
        self.connection = Connection(self.auth_endpoint,
                                     self.user,
                                     self.key,
                                     self.tenant,
                                     authenticate=self.authenticate,
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
        body = {'status': 'ACTIVE',
                'content_types': {'default': 'text/plain'},
                'updated': '2013-06-07T16:13:38.889857',
                'cypher_type': None,
                'name': 'test_secret',
                'algorithm': None,
                'created': '2013-06-07T16:13:38.889851',
                'secret_ref': 'http://localhost:9311/v1/None/secrets/e6e7d'
                              'b5e-3738-408e-aaba-05a7177cade5',
                'expiration': None,
                'bit_length': None,
                'mime_type': 'text/plain'
                }
        self.request.return_value.content = json.dumps(body)
        secret = self.connection.create_secret('text/plain',
                                               'Test secret',
                                               name='test_secret',
                                               algorithm=None,
                                               bit_length=None,
                                               cypher_type=None,
                                               expiration=None)
        self.assertEqual(body['secret_ref'], secret.secret_ref)
        self.assertEqual(self.connection, secret.connection)
        self.assertEqual(body['status'], secret.status)
        self.assertEqual(body['name'], secret.name)
        self.assertEqual(body['mime_type'], secret.mime_type)
        self.assertEqual(parse_isotime(body['created']), secret.created)
        self.assertEqual(parse_isotime(body['updated']), secret.updated)

    def test_should_create_order(self):
        body = {"status": "ACTIVE",
                "secret_ref": "http://localhost:9311/v1/12345/secrets/5706054"
                              "9-2fcf-46eb-92bb-bf49fcf5d089",
                "updated": "2013-06-07T19:00:37.338386",
                "created": "2013-06-07T19:00:37.298704",
                "secret": {
                    "cypher_type": "CDC",
                    "name": "test_secret",
                    "algorithm": "aes",
                    "expiration": None,
                    "bit_length": 256,
                    "mime_type": "text/plain"
                },
                "order_ref": "http://localhost:9311/v1/12345/orders/003f2b91-"
                             "2f53-4c0a-a0f3-33796671efc3"
                }

        self.request.return_value.content = json.dumps(body)
        order = self.connection.create_order('text/plain',
                                             name='test_secret',
                                             bit_length=256,
                                             algorithm='aes',
                                             cypher_type='CDC')
        self.assertEqual(self.connection, order.connection)
        self.assertEqual(body['secret_ref'], order.secret_ref)
        self.assertEqual(body['status'], order.status)
        self.assertEqual(parse_isotime(body['created']), order.created)
        self.assertEqual(parse_isotime(body['updated']), order.updated)
        self.assertEqual(body['secret'], order.secret)


if __name__ == '__main__':
    unittest.main()
