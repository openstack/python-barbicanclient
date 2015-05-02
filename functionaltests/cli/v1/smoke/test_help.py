# Copyright (c) 2015 Rackspace, Inc.
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

from functionaltests.cli.base import CmdLineTestCase
from functionaltests.cli.v1.behaviors import base_behaviors
from functionaltests import utils
from testtools import testcase


@utils.parameterized_test_case
class HelpTestCase(CmdLineTestCase):

    def setUp(self):
        super(HelpTestCase, self).setUp()
        self.help_behaviors = base_behaviors.BaseBehaviors()

    def tearDown(self):
        super(HelpTestCase, self).tearDown()

    @utils.parameterized_dataset({
        'dash_h': [['-h']],
        'doubledash_help': [['--help']]
    })
    @testcase.attr('positive')
    def test_help(self, argv):
        stdout, stderr = self.help_behaviors.issue_barbican_command(argv)
        self.assertIsNotNone(stdout, "{0} returned None".format(argv))
        self.assertGreater(len(stdout), 0, "{0} invalid length".format(argv))
