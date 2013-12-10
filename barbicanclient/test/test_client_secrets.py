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

from barbicanclient.test import test_client
from barbicanclient import secrets
from barbicanclient.openstack.common import timeutils


class SecretData(object):
    def __init__(self):
        self.name = 'Self destruction sequence'
        self.payload = 'the magic words are squeamish ossifrage'
        self.payload_content_type = 'text/plain'
        self.content = 'text/plain'
        self.algorithm = 'AES'
        self.created = str(timeutils.utcnow())

        self.secret_dict = {'name': self.name,
                            'status': 'ACTIVE',
                            'algorithm': self.algorithm,
                            'created': self.created}

    def get_dict(self, secret_ref=None, content_types_dict=None):
        secret = self.secret_dict
        if secret_ref:
            secret['secret_ref'] = secret_ref
        if content_types_dict:
            secret['content_types'] = content_types_dict
        return secret


class WhenTestingSecrets(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('secrets')

        self.secret = SecretData()

        self.manager = secrets.SecretManager(self.api)

    def test_should_entity_str(self):
        secret_obj = secrets.Secret(self.secret.get_dict(self.entity_href))
        self.assertIn('name: ' + self.secret.name,
                      str(secret_obj))

    def test_should_entity_repr(self):
        secret_obj = secrets.Secret(self.secret.get_dict(self.entity_href))
        self.assertIn('name="{0}"'.format(self.secret.name), repr(secret_obj))

    def test_should_store(self):
        self.api.post.return_value = {'secret_ref': self.entity_href}

        secret_href = self.manager\
            .store(name=self.secret.name,
                   payload=self.secret.payload,
                   payload_content_type=self.secret.content)

        self.assertEqual(self.entity_href, secret_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        secret_req = args[1]
        self.assertEqual(self.secret.name, secret_req['name'])
        self.assertEqual(self.secret.payload, secret_req['payload'])
        self.assertEqual(self.secret.payload_content_type,
                         secret_req['payload_content_type'])

    def test_should_get(self):
        self.api.get.return_value = self.secret.get_dict(self.entity_href)

        secret = self.manager.get(secret_ref=self.entity_href)
        self.assertIsInstance(secret, secrets.Secret)
        self.assertEqual(self.entity_href, secret.secret_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_decrypt_with_content_type(self):
        decrypted = 'decrypted text here'
        self.api.get_raw.return_value = decrypted

        secret = self.manager.decrypt(secret_ref=self.entity_href,
                                      content_type='application/octet-stream')
        self.assertEqual(decrypted, secret)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.get_raw.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify that correct information was sent in the call.
        headers = args[1]
        self.assertEqual('application/octet-stream', headers['Accept'])

    def test_should_decrypt_without_content_type(self):
        content_types_dict = {'default': 'application/octet-stream'}
        self.api.get.return_value = self.secret.get_dict(self.entity_href,
                                                         content_types_dict)
        decrypted = 'decrypted text here'
        self.api.get_raw.return_value = decrypted

        secret = self.manager.decrypt(secret_ref=self.entity_href)
        self.assertEqual(decrypted, secret)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.get_raw.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

        # Verify that correct information was sent in the call.
        headers = args[1]
        self.assertEqual('application/octet-stream', headers['Accept'])

    def test_should_delete(self):
        self.manager.delete(secret_ref=self.entity_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.delete.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_get_list(self):
        secret_resp = self.secret.get_dict(self.entity_href)
        self.api.get.return_value = {"secrets":
                                     [secret_resp for v in xrange(3)]}

        secrets_list = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(secrets_list) == 3)
        self.assertIsInstance(secrets_list[0], secrets.Secret)
        self.assertEqual(self.entity_href, secrets_list[0].secret_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.get.call_args
        url = args[0]
        self.assertEqual(self.entity_base[:-1], url)

        # Verify that correct information was sent in the call.
        params = args[1]
        self.assertEqual(10, params['limit'])
        self.assertEqual(5, params['offset'])

    def test_should_fail_get_invalid_secret(self):
        with self.assertRaises(ValueError):
            self.manager.get('12345')

    def test_should_fail_get_no_href(self):
        with self.assertRaises(ValueError):
            self.manager.get(None)

    def test_should_fail_decrypt_no_content_types(self):
        self.api.get.return_value = self.secret.get_dict(self.entity_href)

        with self.assertRaises(ValueError):
            self.manager.decrypt(secret_ref=self.entity_href)

    def test_should_fail_decrypt_no_default_content_type(self):
        content_types_dict = {'no-default': 'application/octet-stream'}
        self.api.get.return_value = self.secret.get_dict(self.entity_href,
                                                         content_types_dict)

        with self.assertRaises(ValueError):
            self.manager.decrypt(secret_ref=self.entity_href)

    def test_should_fail_delete_no_href(self):
        with self.assertRaises(ValueError):
            self.manager.delete(None)
