# Copyright (c) 2017
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

import testtools
import uuid

import barbicanclient
from barbicanclient import base
from barbicanclient import version


class TestValidateRef(testtools.TestCase):

    def test_valid_ref(self):
        secret_uuid = uuid.uuid4()
        ref = 'http://localhost/' + str(secret_uuid)
        self.assertEqual(secret_uuid,
                         base.validate_ref_and_return_uuid(ref, 'Thing'))

    def test_valid_uuid(self):
        secret_uuid = uuid.uuid4()
        self.assertEqual(secret_uuid,
                         base.validate_ref_and_return_uuid(str(secret_uuid),
                                                           'Thing'))

    def test_invalid_uuid(self):
        ref = 'http://localhost/not_a_uuid'
        self.assertRaises(ValueError, base.validate_ref_and_return_uuid, ref,
                          'Thing')

    def test_censored_copy(self):
        d1 = {'a': '1', 'password': 'my_password', 'payload': 'my_key',
              'b': '2'}
        d2 = base.censored_copy(d1, None)
        self.assertEqual(d1, d2, 'd2 contents are unchanged')
        self.assertFalse(d1 is d2, 'd1 and d2 are different instances')
        d3 = base.censored_copy(d1, ['payload'])
        self.assertNotEqual(d1, d3, 'd3 has redacted payload value')
        self.assertNotEqual(d3['payload'], 'my_key', 'no key in payload')

    def test_module_version(self):
        self.assertTrue(hasattr(barbicanclient, '__version__'))
        # Test forward compatibility, please remove the case when all reference
        # switch to barbicanclient.__version__
        self.assertTrue(hasattr(version, '__version__'))
