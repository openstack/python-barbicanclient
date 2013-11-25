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

from barbicanclient import verifications as vers
from barbicanclient.openstack.common import timeutils
from barbicanclient.test import test_client


class VerificationData(object):
    def __init__(self):
        self.created = str(timeutils.utcnow())

        self.resource_type = 'image'
        self.resource_ref = 'http://www.image.com/v1/images/1234'
        self.resource_action = 'vm_attach'
        self.impersonation_allowed = True

        self.verification_dict = {'created': self.created,
                                  'resource_type': self.resource_type,
                                  'resource_ref': self.resource_ref,
                                  'resource_action': self.resource_action,
                                  'impersonation_allowed':
                                  self.impersonation_allowed}

    def get_dict(self, verification_ref):
        verify = self.verification_dict
        verify['verification_ref'] = verification_ref
        return verify


class WhenTestingVerifications(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('verifications')

        self.verify = VerificationData()

        self.manager = vers.VerificationManager(self.api)

    def test_should_entity_str(self):
        verif_obj = vers.Verification(self.verify.get_dict(self.entity_href))
        verif_obj.error_status_code = '500'
        verif_obj.error_reason = 'Something is broken'
        self.assertIn('resource_type: ' + self.verify.resource_type,
                      str(verif_obj))
        self.assertIn('error_status_code: 500', str(verif_obj))

    def test_should_entity_repr(self):
        verif = vers.Verification(self.verify.get_dict(self.entity_href))
        self.assertIn('verification_ref=' + self.entity_href,
                      repr(verif))

    def test_should_create(self):
        self.api.post.return_value = {'verification_ref': self.entity_href}

        order_href = self.manager\
            .create(resource_type=self.verify.resource_type,
                    resource_ref=self.verify.resource_ref,
                    resource_action=self.verify.resource_action)

        self.assertEqual(self.entity_href, order_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.post.call_args
        entity_resp = args[0]
        self.assertEqual(self.entity, entity_resp)

        # Verify that correct information was sent in the call.
        verify_req = args[1]
        self.assertEqual(self.verify.resource_type,
                         verify_req['resource_type'])
        self.assertEqual(self.verify.resource_action,
                         verify_req['resource_action'])
        self.assertEqual(self.verify.resource_ref,
                         verify_req['resource_ref'])

    def test_should_get(self):
        self.api.get.return_value = self.verify.get_dict(self.entity_href)

        verify = self.manager.get(verification_ref=self.entity_href)
        self.assertIsInstance(verify, vers.Verification)
        self.assertEqual(self.entity_href, verify.verif_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.get.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_delete(self):
        self.manager.delete(verification_ref=self.entity_href)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.delete.call_args
        url = args[0]
        self.assertEqual(self.entity_href, url)

    def test_should_get_list(self):
        verify_resp = self.verify.get_dict(self.entity_href)
        self.api.get.return_value = {"verifications":
                                     [verify_resp for v in xrange(3)]}

        verifies = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(verifies) == 3)
        self.assertIsInstance(verifies[0], vers.Verification)
        self.assertEqual(self.entity_href, verifies[0].verif_ref)

        # Verify the correct URL was used to make the call.
        args, kwargs = self.api.get.call_args
        url = args[0]
        self.assertEqual(self.entity_base[:-1], url)

        # Verify that correct information was sent in the call.
        params = args[1]
        self.assertEqual(10, params['limit'])
        self.assertEqual(5, params['offset'])

    def test_should_fail_get_no_href(self):
        with self.assertRaises(ValueError):
            self.manager.get(None)

    def test_should_fail_delete_no_href(self):
        with self.assertRaises(ValueError):
            self.manager.delete(None)
