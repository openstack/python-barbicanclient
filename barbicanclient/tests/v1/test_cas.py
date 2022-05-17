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
from oslo_utils import timeutils

from barbicanclient.tests import test_client
from barbicanclient.v1 import cas


class CAData(object):
    def __init__(self, description='Test CA description'):
        self.name = 'Test CA'
        self.description = description
        self.plugin_name = 'Test CA Plugin'
        self.plugin_ca_id = 'plugin_uuid'

        now = timeutils.utcnow()
        self.expiration = str(now)
        self.created = str(now)

        self.meta = []
        self.meta.append({'name': self.name})
        if self.description:
            self.meta.append({'description': self.description})

        self.ca_dict = {'meta': self.meta,
                        'status': 'ACTIVE',
                        'plugin_name': self.plugin_name,
                        'plugin_ca_id': self.plugin_ca_id,
                        'created': self.created}

    def get_dict(self, ca_ref=None):
        ca = self.ca_dict
        if ca_ref:
            ca['ca_ref'] = ca_ref
        return ca


class WhenTestingCAs(test_client.BaseEntityResource):

    def setUp(self):
        self._setUp('cas')

        self.ca = CAData()
        self.manager = self.client.cas

    def test_should_get_lazy(self, ca_ref=None):
        ca_ref = ca_ref or self.entity_href

        data = self.ca.get_dict(ca_ref)
        m = self.responses.get(self.entity_href, json=data)

        ca = self.manager.get(ca_ref=ca_ref)
        self.assertIsInstance(ca, cas.CA)
        self.assertEqual(ca_ref, ca._ca_ref)

        # Verify GET wasn't called yet
        self.assertFalse(m.called)

        # Check an attribute to trigger lazy-load
        self.assertEqual(self.ca.plugin_ca_id, ca.plugin_ca_id)

        # Verify the correct URL was used to make the GET call
        self.assertEqual(self.entity_href, m.last_request.url)

    def test_should_get_lazy_using_stripped_uuid(self):
        bad_href = "http://badsite.com/" + self.entity_id
        self.test_should_get_lazy(bad_href)

    def test_should_get_lazy_using_only_uuid(self):
        self.test_should_get_lazy(self.entity_id)

    def test_should_get_lazy_in_meta(self):
        data = self.ca.get_dict(self.entity_href)
        m = self.responses.get(self.entity_href, json=data)

        ca = self.manager.get(ca_ref=self.entity_href)
        self.assertIsInstance(ca, cas.CA)
        self.assertEqual(self.entity_href, ca._ca_ref)

        # Verify GET wasn't called yet
        self.assertFalse(m.called)

        # Check an attribute in meta to trigger lazy-load
        self.assertEqual(self.ca.name, ca.name)

        # Verify the correct URL was used to make the GET call
        self.assertEqual(self.entity_href, m.last_request.url)

    def test_should_get_list(self):
        ca_resp = self.entity_href

        data = {"cas": [ca_resp for v in range(3)]}
        m = self.responses.get(self.entity_base, json=data)

        ca_list = self.manager.list(limit=10, offset=5)
        self.assertTrue(len(ca_list) == 3)
        self.assertIsInstance(ca_list[0], cas.CA)
        self.assertEqual(self.entity_href, ca_list[0].ca_ref)

        # Verify the correct URL was used to make the call.
        self.assertEqual(self.entity_base,
                         m.last_request.url.split('?')[0])

        # Verify that correct information was sent in the call.
        self.assertEqual(['10'], m.last_request.qs['limit'])
        self.assertEqual(['5'], m.last_request.qs['offset'])

    def test_should_fail_get_invalid_ca(self):
        self.assertRaises(ValueError, self.manager.get,
                          **{'ca_ref': '12345'})

    def test_should_get_ca_that_has_no_meta_description(self):
        self.ca = CAData(description=None)

        data = self.ca.get_dict(self.entity_href)
        m = self.responses.get(self.entity_href, json=data)

        ca = self.manager.get(ca_ref=self.entity_href)
        self.assertIsInstance(ca, cas.CA)
        self.assertEqual(self.entity_href, ca._ca_ref)

        # Verify GET wasn't called yet
        self.assertFalse(m.called)

        # Get description from CA, check it is None
        self.assertIsNone(self.ca.description)
        self.assertIsNone(ca.description)

        # Verify the correct URL was used to make the GET call
        self.assertEqual(self.entity_href, m.last_request.url)

    def test_get_formatted_data(self):
        c_entity = cas.CA(api=None,
                          expiration=self.ca.expiration,
                          plugin_name=self.ca.plugin_name,
                          created=self.ca.created)

        data = c_entity._get_formatted_data()

        self.assertEqual(self.ca.plugin_name, data[6])
        self.assertEqual(timeutils.parse_isotime(
                         self.ca.expiration).isoformat(),
                         data[8])
