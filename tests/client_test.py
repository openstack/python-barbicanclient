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

from barbicanclient.client import Connection, Order, Secret
from barbicanclient.common.exceptions import ClientException


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
                'cypher_type': 'CDC',
                'name': 'test_secret',
                'algorithm': 'aes',
                'created': '2013-06-07T16:13:38.889851',
                'secret_ref': 'http://localhost:9311/v1/None/secrets/e6e7d'
                              'b5e-3738-408e-aaba-05a7177cade5',
                'expiration': '2015-06-07T16:13:38.889851',
                'bit_length': 256,
                'mime_type': 'text/plain'
                }

        secret = Secret(self.connection, body)
        self.request.return_value.content = json.dumps(body)
        created = self.connection.create_secret('text/plain',
                                                'Test secret',
                                                name='test_secret',
                                                algorithm=None,
                                                bit_length=None,
                                                cypher_type=None,
                                                expiration=None)
        self.assertEqual(secret, created)

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
                    "expiration": "2015-06-07T19:00:37.298704",
                    "bit_length": 256,
                    "mime_type": "text/plain"
                },
                "order_ref": "http://localhost:9311/v1/12345/orders/003f2b91-"
                             "2f53-4c0a-a0f3-33796671efc3"
                }

        order = Order(self.connection, body)
        self.request.return_value.content = json.dumps(body)
        created = self.connection.create_order('text/plain',
                                               name='test_secret',
                                               bit_length=256,
                                               algorithm='aes',
                                               cypher_type='CDC')
        self.assertEqual(order, created)

    def test_should_list_secrets(self):
        body0 = {'secrets': []}
        secrets = []
        self.request.return_value.content = json.dumps(body0)
        self.assertEquals(secrets, self.connection.list_secrets())

        body1 = {'secrets': [{'status': 'ACTIVE',
                             'content_types': {'default': 'text/plain'},
                             'updated': '2013-06-03T21:16:58.349230',
                             'cypher_type': None,
                             'name': 'test_1',
                             'algorithm': None,
                             'created': '2013-06-03T21:16:58.349222',
                             'secret_ref': 'http://localhost:9311/v1/'
                                           'None/secrets/bbd2036f-730'
                                           '7-4090-bbef-bbb6025e5e7b',
                             'expiration': None,
                             'bit_length': None,
                             'mime_type': 'text/plain'}]}
        secrets.append(Secret(self.connection, body1['secrets'][0]))
        self.request.return_value.content = json.dumps(body1)
        self.assertEquals(secrets, self.connection.list_secrets())

        body2 = {'secrets': [{'status': 'ACTIVE',
                             'content_types': {'default': 'text/plain'},
                             'updated': '2013-07-03T21:17:58.349230',
                             'cypher_type': None,
                             'name': 'test_2',
                             'algorithm': 'aes',
                             'created': '2013-06-03T21:16:58.349222',
                             'secret_ref': 'http://localhost:9311/v1/'
                                           'None/secrets/bbd2036f-730'
                                           '7-4090-bbef-bbb6025eabcd',
                             'expiration': None,
                             'bit_length': None,
                             'mime_type': 'text/plain'}]}
        secrets.append(Secret(self.connection, body2['secrets'][0]))
        body2['secrets'].insert(0, body1['secrets'][0])
        self.request.return_value.content = json.dumps(body2)
        self.assertEquals(secrets, self.connection.list_secrets())

    def test_should_list_orders(self):
        body0 = {'orders': []}
        orders = []
        self.request.return_value.content = json.dumps(body0)
        self.assertEquals(orders, self.connection.list_orders())

        body1 = {'orders': [{'status': 'PENDING',
                             'updated': '2013-06-05T15:15:30.904760',
                             'created': '2013-06-05T15:15:30.904752',
                             'order_ref': 'http://localhost:9311/v1/'
                                          'None/orders/9f651441-3ccd'
                                          '-45b3-bc60-3051656d5168',
                             'secret_ref': 'http://localhost:9311/'
                                           'v1/None/secrets/????',
                             'secret': {'cypher_type': None,
                                        'name': 'test_1',
                                        'algorithm': None,
                                        'expiration': None,
                                        'bit_length': None,
                                        'mime_type': 'text/plain'}}]}
        orders.append(Order(self.connection, body1['orders'][0]))
        self.request.return_value.content = json.dumps(body1)
        self.assertEquals(orders, self.connection.list_orders())

        body2 = {'orders': [{'status': 'ACTIVE',
                             'updated': '2013-07-05T15:15:30.904938',
                             'created': '2013-07-05T15:15:30.904752',
                             'order_ref': 'http://localhost:9311/v1/'
                                          'None/orders/9f651441-3ccd'
                                          '-45b3-bc60-3051656382fj',
                             'secret_ref': 'http://localhost:9311/'
                                           'v1/None/secrets/????',
                             'secret': {'cypher_type': None,
                                        'name': 'test_2',
                                        'algorithm': None,
                                        'expiration': None,
                                        'bit_length': None,
                                        'mime_type': 'text/plain'}}]}
        orders.append(Order(self.connection, body2['orders'][0]))
        body2['orders'].insert(0, body1['orders'][0])
        self.request.return_value.content = json.dumps(body2)
        self.assertEquals(orders, self.connection.list_orders())

    def test_should_perform_http(self):
        href = 'http://localhost:9311/v1/12345/orders'
        self.request.return_value.headers = {'Accept': 'application/json'}
        self.request.return_value.content = ''
        headers, body = self.connection._perform_http('GET', href)
        self.assertEqual(self.request.return_value.headers, headers)
        self.assertEqual(self.request.return_value.content, body)

        self.request.return_value.content = '{"test": "response"}'

        headers, body = self.connection._perform_http('GET', href,
                                                      parse_json=True)
        self.assertEqual(json.loads(self.request.return_value.content), body)

        headers, body = self.connection._perform_http('GET', href,
                                                      parse_json=False)
        self.assertEqual(self.request.return_value.content, body)

        self.request.return_value.ok = False
        with self.assertRaises(ClientException):
            self.connection._perform_http('GET', href)


if __name__ == '__main__':
    unittest.main()
