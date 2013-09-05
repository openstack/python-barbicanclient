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

import cStringIO
import os
import sys
import unittest2 as unittest

import barbicanclient.keep


def suite():
    suite = unittest.TestSuite()

    suite.addTest(TestKeep())

    return suite


class TestKeep(unittest.TestCase):
    def keep(self, argstr):
        """Source: Keystone client's shell method in test_shell.py"""
        orig = sys.stdout
        clean_env = {}
        _old_env, os.environ = os.environ, clean_env.copy()
        try:
            sys.stdout = cStringIO.StringIO()
            _keep = barbicanclient.keep.Keep()
            _keep.execute(argv=argstr.split())
        except SystemExit:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.assertEqual(exc_value.code, 0)
        finally:
            out = sys.stdout.getvalue()
            sys.stdout.close()
            sys.stdout = orig
            os.environ = _old_env
        return out

    def setUp(self):
        pass

    def test_help(self):
        args = "-h"
        self.assertIn('usage: ', self.keep(args))

if __name__ == '__main__':
    unittest.main()
