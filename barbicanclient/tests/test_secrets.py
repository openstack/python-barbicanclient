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

import json

from oslo.utils import timeutils

from barbicanclient.tests import test_client
from barbicanclient import secrets, base


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
        self.manager = self.client.secrets

    def test_should_entity_str(self):
        secret_obj = self.manager.create(name=self.secret.name)
        self.assertIn(self.secret.name, str(secret_obj))

    def test_should_entity_repr(self):
        secret_obj = self.manager.create(name=self.secret.name)
        self.assertIn('name="{0}"'.format(self.secret.name), repr(secret_obj))

    def test_should_store_via_constructor(self):
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create(name=self.secret.name,
                                     payload=self.secret.payload,
                                     payload_content_type=self.secret.content)
        secret_href = secret.store()
        self.assertEqual(self.entity_href, secret_href)

        # Verify that correct information was sent in the call.
        secret_req = json.loads(self.responses.last_request.text)
        self.assertEqual(self.secret.name, secret_req['name'])
        self.assertEqual(self.secret.payload, secret_req['payload'])
        self.assertEqual(self.secret.payload_content_type,
                         secret_req['payload_content_type'])

    def test_should_store_via_attributes(self):
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create()
        secret.name = self.secret.name
        secret.payload = self.secret.payload
        secret.payload_content_type = self.secret.content
        secret_href = secret.store()
        self.assertEqual(self.entity_href, secret_href)

        # Verify that correct information was sent in the call.
        secret_req = json.loads(self.responses.last_request.text)
        self.assertEqual(self.secret.name, secret_req['name'])
        self.assertEqual(self.secret.payload, secret_req['payload'])
        self.assertEqual(self.secret.payload_content_type,
                         secret_req['payload_content_type'])

    def test_should_be_immutable_after_submit(self):
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create(name=self.secret.name,
                                     payload=self.secret.payload,
                                     payload_content_type=self.secret.content)
        secret_href = secret.store()

        self.assertEqual(self.entity_href, secret_href)

        # Verify that attributes are immutable after store.
        attributes = [
            "name", "expiration", "algorithm", "bit_length", "mode", "payload",
            "payload_content_type", "payload_content_encoding"
        ]
        for attr in attributes:
            try:
                setattr(secret, attr, "test")
                self.fail("didn't raise an ImmutableException exception")
            except base.ImmutableException:
                pass

    def test_should_not_be_able_to_set_generated_attributes(self):
        secret = self.manager.create()

        # Verify that generated attributes cannot be set.
        attributes = [
            "secret_ref", "created", "updated", "content_types", "status"
        ]
        for attr in attributes:
            try:
                setattr(secret, attr, "test")
                self.fail("didn't raise an AttributeError exception")
            except AttributeError:
                pass

    def test_should_get_lazy(self):
        data = self.secret.get_dict(self.entity_href)
        m = self.responses.get(self.entity_href, json=data)

        secret = self.manager.get(secret_ref=self.entity_href)
        self.assertIsInstance(secret, secrets.Secret)
        self.assertEqual(self.entity_href, secret.secret_ref)

        # Verify GET wasn't called yet
        self.assertFalse(m.called)

        # Check an attribute to trigger lazy-load
        self.assertEqual(self.secret.name, secret.name)

        # Verify the correct URL was used to make the GET call
        self.assertEqual(self.entity_href, m.last_request.url)

    def test_should_get_payload_only(self):
        m = self.responses.get(self.entity_href,
                               request_headers={'Accept': 'application/json'},
                               json=self.secret.get_dict(self.entity_href))
        n = self.responses.get(self.entity_href,
                               request_headers={'Accept': 'text/plain'},
                               text=self.secret.payload)

        secret = self.manager.get(
            secret_ref=self.entity_href,
            payload_content_type=self.secret.payload_content_type
        )
        self.assertIsInstance(secret, secrets.Secret)
        self.assertEqual(self.entity_href, secret.secret_ref)

        # Verify `get` wasn't called yet (metadata)
        self.assertFalse(m.called)

        # Verify `get_raw` wasn't called yet (payload)
        self.assertFalse(n.called)

        # GET payload (with payload_content_type)
        self.assertEqual(self.secret.payload, secret.payload)

        # Verify `get` still wasn't called (metadata)
        self.assertFalse(m.called)

        # Verify `get_raw` was called (payload)
        self.assertTrue(n.called)

        # Verify the correct URL was used to make the `get_raw` call
        self.assertEqual(self.entity_href, n.last_request.url)

    def test_should_fetch_metadata_to_get_payload_if_no_content_type_set(self):
        content_types_dict = {'default': 'application/octet-stream'}

        data = self.secret.get_dict(self.entity_href,
                                    content_types_dict=content_types_dict)
        m = self.responses.get(self.entity_href,
                               request_headers={'Accept': 'application/json'},
                               json=data)

        request_headers = {'Accept': 'application/octet-stream'}
        n = self.responses.get(self.entity_href,
                               request_headers=request_headers,
                               text=self.secret.payload)

        secret = self.manager.get(secret_ref=self.entity_href)
        self.assertIsInstance(secret, secrets.Secret)
        self.assertEqual(self.entity_href, secret.secret_ref)

        # Verify `get` wasn't called yet (metadata)
        self.assertFalse(m.called)

        # Verify `get_raw` wasn't called yet (payload)
        self.assertFalse(n.called)

        # GET payload (with no payload_content_type) trigger lazy-load
        self.assertEqual(self.secret.payload, secret.payload)

        # Verify `get` was called (metadata)
        self.assertTrue(m.called)

        # Verify `get_raw` was called (payload)
        self.assertTrue(n.called)

        # Verify the correct URL was used to make the `get` calls
        self.assertEqual(self.entity_href, m.last_request.url)
        self.assertEqual(self.entity_href, n.last_request.url)

    def test_should_decrypt_with_content_type(self):
        decrypted = 'decrypted text here'

        request_headers = {'Accept': 'application/octet-stream'}

        m = self.responses.get(self.entity_href,
                               request_headers=request_headers,
                               text=decrypted)

        secret = self.manager.get(
            secret_ref=self.entity_href,
            payload_content_type='application/octet-stream'
        )
        secret_payload = secret.payload
        self.assertEqual(decrypted, secret_payload)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, m.last_request.url)

    def test_should_decrypt_without_content_type(self):
        content_types_dict = {'default': 'application/octet-stream'}
        json = self.secret.get_dict(self.entity_href, content_types_dict)
        m = self.responses.get(self.entity_href,
                               request_headers={'Accept': 'application/json'},
                               json=json)

        decrypted = 'decrypted text here'
        request_headers = {'Accept': 'application/octet-stream'}
        n = self.responses.get(self.entity_href,
                               request_headers=request_headers,
                               text=decrypted)

        secret = self.manager.get(secret_ref=self.entity_href)
        secret_payload = secret.payload
        self.assertEqual(decrypted, secret_payload)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, m.last_request.url)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, n.last_request.url)

    def test_should_delete(self):
        self.responses.delete(self.entity_href, status_code=204)

        self.manager.delete(secret_ref=self.entity_href)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

    def test_should_get_list(self):
        secret_resp = self.secret.get_dict(self.entity_href)

        data = {"secrets": [secret_resp for v in range(3)]}
        m = self.responses.get(self.entity_base, json=data)

        secrets_list = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(secrets_list) == 3)
        self.assertIsInstance(secrets_list[0], secrets.Secret)
        self.assertEqual(self.entity_href, secrets_list[0].secret_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base,
                         m.last_request.url.split('?')[0])

        # Verify that correct information was sent in the call.
        self.assertEqual(['10'], m.last_request.qs['limit'])
        self.assertEqual(['5'], m.last_request.qs['offset'])

    def test_should_fail_get_invalid_secret(self):
        self.assertRaises(ValueError, self.manager.get,
                          **{'secret_ref': '12345'})

    def test_should_fail_decrypt_no_content_types(self):
        data = self.secret.get_dict(self.entity_href)
        self.responses.get(self.entity_href, json=data)
        secret = self.manager.get(secret_ref=self.entity_href)

        try:
            secret.payload
            self.fail("didn't raise a ValueError exception")
        except ValueError:
            pass

    def test_should_fail_decrypt_no_default_content_type(self):
        content_types_dict = {'no-default': 'application/octet-stream'}
        data = self.secret.get_dict(self.entity_href, content_types_dict)
        self.responses.get(self.entity_href, json=data)

        secret = self.manager.get(secret_ref=self.entity_href)
        try:
            secret.payload
            self.fail("didn't raise a ValueError exception")
        except ValueError:
            pass

    def test_should_fail_delete_no_href(self):
        self.assertRaises(ValueError, self.manager.delete, None)

    def test_should_get_total(self):
        self.responses.get(self.entity_base, json={'total': 1})
        total = self.manager.total()
        self.assertEqual(total, 1)
