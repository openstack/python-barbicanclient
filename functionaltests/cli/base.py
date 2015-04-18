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
import six

from functionaltests.base import BaseTestCase
from barbicanclient import barbican


class CmdLineTestCase(BaseTestCase):

    def setUp(self):
        self.LOG.info('Starting: %s', self._testMethodName)
        super(CmdLineTestCase, self).setUp()

        self.cmdline_client = barbican.Barbican()

    def issue_barbican_command(self, argv):
        """ Issue the barbican command and return its output.

        The barbican command sometimes raises SystemExit, but not always, so
        we will handle either situation here.

        Also we will create new stdout/stderr streams for each command so that
        any output from a previous command doesn't contaminate the new command.

        :param argv: dict of keyword arguments to pass to the command.  This
        does NOT include "barbican" - that's not needed.
        :return: Two strings - one the captured stdout and one the captured
        stderr.
        """

        try:
            self.cmdline_client.stdout = six.StringIO()
            self.cmdline_client.stderr = six.StringIO()
            self.cmdline_client.run(argv)
        except exc.SystemExit:
            pass

        outstr = self.cmdline_client.stdout.getvalue()
        errstr = self.cmdline_client.stderr.getvalue()

        return outstr, errstr
