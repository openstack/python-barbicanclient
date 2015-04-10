"""
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import exceptions as exc

from functionaltests.base import BaseTestCase
from barbicanclient import barbican


class CmdLineTestCase(BaseTestCase):

    def setUp(self):
        self.LOG.info('Starting: %s', self._testMethodName)
        super(CmdLineTestCase, self).setUp()

        self.cmdline_client = barbican.Barbican()

    def issue_barbican_command(self, argv):
        """ Issue the barbican command and return its output.

        :param argv: dict of keyword arguments to pass to the command.  This
        does NOT include "barbican" - that's not needed.
        :return: list of strings returned by the command, one list element
        per line of output.  This means the caller doesn't have to worry about
        parsing newlines, etc.  If there is a problem then this method
        will return None
        """
        result = None
        try:
            self.cmdline_client.run(argv)
        except exc.SystemExit:
            result = self.cmdline_client.stdout.getvalue()
        return result
