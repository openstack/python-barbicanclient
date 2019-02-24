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

import base64

from oslo_serialization import jsonutils
from oslo_utils import timeutils

from barbicanclient import base
from barbicanclient import exceptions
from barbicanclient.tests import test_client
from barbicanclient.v1 import acls
from barbicanclient.v1 import secrets


class SecretData(object):
    def __init__(self):
        self.name = u'Self destruction sequence'
        self.payload = u'the magic words are squeamish ossifrage'
        self.payload_content_type = u'text/plain'
        self.algorithm = u'AES'
        self.created = str(timeutils.utcnow())

        self.secret_dict = {'name': self.name,
                            'status': u'ACTIVE',
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
                                     payload=self.secret.payload)
        secret_href = secret.store()
        self.assertEqual(self.entity_href, secret_href)

        # Verify that correct information was sent in the call.
        secret_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.secret.name, secret_req['name'])
        self.assertEqual(self.secret.payload, secret_req['payload'])

    def test_should_store_via_attributes(self):
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create()
        secret.name = self.secret.name
        secret.payload = self.secret.payload
        secret_href = secret.store()
        self.assertEqual(self.entity_href, secret_href)

        # Verify that correct information was sent in the call.
        secret_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.secret.name, secret_req['name'])
        self.assertEqual(self.secret.payload, secret_req['payload'])

    def test_should_store_binary_type_as_octet_stream(self):
        """We use six.binary_type as the canonical binary type.

        The client should base64 encode the payload before sending the
        request.
        """
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        # This literal will have type(str) in Python 2, but will have
        # type(bytes) in Python 3.  It is six.binary_type in both cases.
        binary_payload = b'F\x130\x89f\x8e\xd9\xa1\x0e\x1f\r\xf67uu\x8b'

        secret = self.manager.create()
        secret.name = self.secret.name
        secret.payload = binary_payload
        secret.store()

        secret_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(self.secret.name, secret_req['name'])
        self.assertEqual(u'application/octet-stream',
                         secret_req['payload_content_type'])
        self.assertEqual(u'base64',
                         secret_req['payload_content_encoding'])
        self.assertNotEqual(binary_payload, secret_req['payload'])

    def test_should_store_text_type_as_text_plain(self):
        """We use six.text_type as the canonical text type."""
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        # This literal will have type(unicode) in Python 2, but will have
        # type(str) in Python 3.  It is six.text_type in both cases.
        text_payload = u'time for an ice cold \U0001f37a'

        secret = self.manager.create()
        secret.payload = text_payload
        secret.store()

        secret_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(text_payload, secret_req['payload'])
        self.assertEqual(u'text/plain', secret_req['payload_content_type'])

    def test_should_store_with_deprecated_content_type(self):
        """DEPRECATION WARNING

        Manually setting the payload_content_type is deprecated and will be
        removed in a future release.
        """
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        payload = 'I should be octet-stream'
        payload_content_type = u'text/plain'

        secret = self.manager.create()
        secret.payload = payload
        secret.payload_content_type = payload_content_type
        secret.store()

        secret_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(payload, secret_req['payload'])
        self.assertEqual(payload_content_type,
                         secret_req['payload_content_type'])

    def test_should_store_with_deprecated_content_encoding(self):
        """DEPRECATION WARNING

        Manually setting the payload_content_encoding is deprecated and will be
        removed in a future release.
        """
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        encoded_payload = base64.b64encode(
            b'F\x130\x89f\x8e\xd9\xa1\x0e\x1f\r\xf67uu\x8b'
        ).decode('UTF-8')
        payload_content_type = u'application/octet-stream'
        payload_content_encoding = u'base64'

        secret = self.manager.create()
        secret.payload = encoded_payload
        secret.payload_content_type = payload_content_type
        secret.payload_content_encoding = payload_content_encoding
        secret.store()

        secret_req = jsonutils.loads(self.responses.last_request.text)
        self.assertEqual(encoded_payload, secret_req['payload'])
        self.assertEqual(payload_content_type,
                         secret_req['payload_content_type'])
        self.assertEqual(payload_content_encoding,
                         secret_req['payload_content_encoding'])

    def test_should_be_immutable_after_submit(self):
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create(name=self.secret.name,
                                     payload=self.secret.payload)
        secret_href = secret.store()

        self.assertEqual(self.entity_href, secret_href)

        # Verify that attributes are immutable after store.
        attributes = [
            "name", "expiration", "algorithm", "bit_length", "mode",
            "payload_content_type", "payload_content_encoding", "secret_type"]
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

    def test_should_get_lazy(self, secret_ref=None):
        secret_ref = secret_ref or self.entity_href

        data = self.secret.get_dict(secret_ref)
        m = self.responses.get(self.entity_href, json=data)

        secret = self.manager.get(secret_ref=secret_ref)
        self.assertIsInstance(secret, secrets.Secret)
        self.assertEqual(secret_ref, secret.secret_ref)

        # Verify GET wasn't called yet
        self.assertFalse(m.called)

        # Check an attribute to trigger lazy-load
        self.assertEqual(self.secret.name, secret.name)

        # Verify the correct URL was used to make the GET call
        self.assertEqual(self.entity_href, m.last_request.url)

    def test_should_get_lazy_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_get_lazy(bad_href)

    def test_should_get_lazy_using_only_uuid(self):
        self.test_should_get_lazy(self.entity_id)

    def test_should_get_acls_lazy(self):
        data = self.secret.get_dict(self.entity_href)
        m = self.responses.get(self.entity_href, json=data)

        acl_data = {'read': {'project-access': True, 'users': ['u1']}}
        acl_ref = self.entity_href + '/acl'
        n = self.responses.get(acl_ref, json=acl_data)

        secret = self.manager.get(secret_ref=self.entity_href)
        self.assertIsNotNone(secret)

        self.assertEqual(self.secret.name, secret.name)
        # Verify GET was called for secret but for acl it was not called
        self.assertTrue(m.called)
        self.assertFalse(n.called)

        # Check an attribute to trigger lazy-load
        self.assertEqual(['u1'], secret.acls.read.users)
        self.assertTrue(secret.acls.read.project_access)
        self.assertIsInstance(secret.acls, acls.SecretACL)

        # Verify the correct URL was used to make the GET call
        self.assertEqual(acl_ref, n.last_request.url)

    def test_should_get_payload_only_when_content_type_is_set(self):
        """DEPRECATION WARNING

        Manually setting the payload_content_type is deprecated and will be
        removed in a future release.
        """
        m = self.responses.get(self.entity_href,
                               request_headers={'Accept': 'application/json'},
                               json=self.secret.get_dict(self.entity_href))
        n = self.responses.get(self.entity_payload_href,
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
        self.assertEqual(self.entity_payload_href, n.last_request.url)

    def test_should_fetch_metadata_to_get_payload(self):
        content_types_dict = {'default': 'text/plain'}

        data = self.secret.get_dict(self.entity_href,
                                    content_types_dict=content_types_dict)
        metadata_response = self.responses.get(
            self.entity_href,
            request_headers={'Accept': 'application/json'},
            json=data)

        request_headers = {'Accept': 'text/plain'}
        decryption_response = self.responses.get(
            self.entity_payload_href,
            request_headers=request_headers,
            text=self.secret.payload)

        secret = self.manager.get(secret_ref=self.entity_href)
        self.assertIsInstance(secret, secrets.Secret)
        self.assertEqual(self.entity_href, secret.secret_ref)

        # Verify `get` wasn't called yet (metadata)
        self.assertFalse(metadata_response.called)

        # Verify `get_raw` wasn't called yet (payload)
        self.assertFalse(decryption_response.called)

        # GET payload (with no payload_content_type) trigger lazy-load
        self.assertEqual(self.secret.payload, secret.payload)

        # Verify `get` was called (metadata)
        self.assertTrue(metadata_response.called)

        # Verify `get_raw` was called (payload)
        self.assertTrue(decryption_response.called)

        # Verify the correct URL was used to make the `get` calls
        self.assertEqual(self.entity_href, metadata_response.last_request.url)
        self.assertEqual(self.entity_payload_href,
                         decryption_response.last_request.url)

    def test_should_decrypt_when_content_type_is_set(self):
        """DEPRECATION WARNING

        Manually setting the payload_content_type is deprecated and will be
        removed in a future release.
        """
        decrypted = b'decrypted text here'

        request_headers = {'Accept': 'application/octet-stream'}

        m = self.responses.get(self.entity_payload_href,
                               request_headers=request_headers,
                               content=decrypted)

        secret = self.manager.get(
            secret_ref=self.entity_href,
            payload_content_type='application/octet-stream'
        )
        secret_payload = secret.payload
        self.assertEqual(decrypted, secret_payload)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_payload_href, m.last_request.url)

    def test_should_decrypt(self, secret_ref=None):
        secret_ref = secret_ref or self.entity_href

        content_types_dict = {'default': 'application/octet-stream'}
        json = self.secret.get_dict(secret_ref, content_types_dict)
        metadata_response = self.responses.get(
            self.entity_href,
            request_headers={'Accept': 'application/json'},
            json=json)

        decrypted = b'decrypted text here'
        request_headers = {'Accept': 'application/octet-stream'}
        decryption_response = self.responses.get(
            self.entity_payload_href,
            request_headers=request_headers,
            content=decrypted)

        secret = self.manager.get(secret_ref=secret_ref)
        secret_payload = secret.payload
        self.assertEqual(decrypted, secret_payload)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, metadata_response.last_request.url)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_payload_href,
                         decryption_response.last_request.url)

    def test_should_decrypt_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_decrypt(bad_href)

    def test_should_delete_from_manager(self, secret_ref=None):
        secret_ref = secret_ref or self.entity_href

        self.responses.delete(self.entity_href, status_code=204)

        self.manager.delete(secret_ref=secret_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

    def test_should_delete_from_manager_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_delete_from_manager(bad_href)

    def test_should_delete_from_manager_using_only_uuid(self):
        self.test_should_delete_from_manager(self.entity_id)

    def test_should_delete_from_object(self, secref_ref=None):
        secref_ref = secref_ref or self.entity_href
        data = {'secret_ref': secref_ref}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create()
        secret.payload = None
        secret.store()

        # Verify the secret has the correct ref for testing deletes
        self.assertEqual(secref_ref, secret.secret_ref)

        self.responses.delete(self.entity_href, status_code=204)

        secret.delete()

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

    def test_should_delete_from_object_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_delete_from_object(bad_href)

    def test_should_delete_from_object_using_only_uuid(self):
        self.test_should_delete_from_object(self.entity_id)

    def test_should_update_from_manager(self, secret_ref=None):
        # This literal will have type(unicode) in Python 2, but will have
        # type(str) in Python 3.  It is six.text_type in both cases.
        text_payload = u'time for an ice cold \U0001f37a'
        secret_ref = secret_ref or self.entity_href

        self.responses.put(self.entity_href, status_code=204)

        self.manager.update(secret_ref=secret_ref, payload=text_payload)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

    def test_should_update_from_manager_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_update_from_manager(bad_href)

    def test_should_update_from_manager_using_only_uuid(self):
        self.test_should_update_from_manager(self.entity_id)

    def test_should_update_from_object(self, secref_ref=None):
        secref_ref = secref_ref or self.entity_href
        data = {'secret_ref': secref_ref}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create()
        secret.payload = None
        secret.store()

        # Verify the secret has the correct ref for testing updates
        self.assertEqual(secref_ref, secret.secret_ref)

        # This literal will have type(unicode) in Python 2, but will have
        # type(str) in Python 3.  It is six.text_type in both cases.
        text_payload = u'time for an ice cold \U0001f37a'

        self.responses.put(self.entity_href, status_code=204)

        secret.payload = text_payload
        secret.update()

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_href, self.responses.last_request.url)

        # Verify that the data has been updated
        self.assertEqual(text_payload, secret.payload)

    def test_should_update_from_object_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_update_from_object(bad_href)

    def test_should_update_from_object_using_only_uuid(self):
        self.test_should_update_from_object(self.entity_id)

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

    def test_should_fail_update_zero(self):
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create()
        secret.payload = None
        secret.store()

        self.responses.put(self.entity_href, status_code=204)
        secret.payload = 0

        # Verify that an error is thrown
        self.assertRaises(exceptions.PayloadException, secret.update)

    def test_should_fail_store_zero(self):
        data = {'secret_ref': self.entity_href}
        self.responses.post(self.entity_base + '/', json=data)

        secret = self.manager.create()
        secret.name = self.secret.name
        secret.payload = 0

        self.assertRaises(exceptions.PayloadException, secret.store)

    def test_should_fail_decrypt_no_content_types(self):
        data = self.secret.get_dict(self.entity_href)
        self.responses.get(self.entity_href, json=data)
        secret = self.manager.get(secret_ref=self.entity_href)

        self.assertIsNone(secret.payload)

    def test_should_fail_decrypt_no_default_content_type(self):
        content_types_dict = {'no-default': 'application/octet-stream'}
        data = self.secret.get_dict(self.entity_href, content_types_dict)
        self.responses.get(self.entity_href, json=data)

        secret = self.manager.get(secret_ref=self.entity_href)
        self.assertIsNone(secret.payload)

    def test_should_fail_delete_no_href(self):
        self.assertRaises(ValueError, self.manager.delete, None)

    def test_should_get_total(self):
        self.responses.get(self.entity_base, json={'total': 1})
        total = self.manager.total()
        self.assertEqual(1, total)

    def test_get_formatted_data(self):
        data = self.secret.get_dict(self.entity_href)
        self.responses.get(self.entity_href, json=data)

        secret = self.manager.get(secret_ref=self.entity_href)
        f_data = secret._get_formatted_data()
        self.assertEqual(
            timeutils.parse_isotime(data['created']).isoformat(),
            f_data[2])
