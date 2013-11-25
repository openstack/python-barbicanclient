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

from barbicanclient import verifications as verify
from barbicanclient.openstack.common import timeutils
from barbicanclient.test import test_client
from barbicanclient.test import test_client_secrets as test_secrets


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


class WhenTestingVerificationsManager(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('verifications')

        self.verify = VerificationData()

        self.manager = verify.VerificationManager(self.api)

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
        self.assertEqual(self.verify.resource_type, verify_req['resource_type'])
        self.assertEqual(self.verify.resource_action,
                         verify_req['resource_action'])
        self.assertEqual(self.verify.resource_ref,
                         verify_req['resource_ref'])

    # def test_should_get(self):
    #     self.api.get.return_value = self.order.get_dict(self.entity_href)
    #
    #     order = self.manager.get(order_ref=self.entity_href)
    #     self.assertIsInstance(order, orders.Order)
    #     self.assertEqual(self.entity_href, order.order_ref)
    #
    #     # Verify the correct URL was used to make the call.
    #     args, kwargs = self.api.get.call_args
    #     url = args[0]
    #     self.assertEqual(self.entity_href, url)
    #
    # def test_should_delete(self):
    #     self.manager.delete(order_ref=self.entity_href)
    #
    #     # Verify the correct URL was used to make the call.
    #     args, kwargs = self.api.delete.call_args
    #     url = args[0]
    #     self.assertEqual(self.entity_href, url)
    #
    # def test_should_fail_get_no_href(self):
    #     with self.assertRaises(ValueError):
    #         self.manager.get(None)
    #
    # def test_should_fail_delete_no_href(self):
    #     with self.assertRaises(ValueError):
    #         self.manager.delete(None)
