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
import logging
import re
import six

from barbicanclient import barbican
from functionaltests.common import config

CONF = config.get_config()


class BaseBehaviors(object):

    def __init__(self):
        self.LOG = logging.getLogger(type(self).__name__)
        self.cmdline_client = barbican.Barbican()

    def add_auth_and_endpoint(self, arg_list):
        """Update an argument list with authentication and endpoint data

        Keystone v3 introduced the concept of a domain, so only the v3
        flavor will include domain names.

        Keystone v3 changed "tenant" to "project" so the v3 flavor uses
        the term 'project' in its args while v2 uses 'tenant'.

        Both v2 and v2 require the auth URL, userid/password, and barbican
        endpoint URL.

        :param arg_list: the current argument list
        :return: the argument list is updated with the authentication and
        endpoint args
        """

        if 'v3' in CONF.identity.auth_version.lower():
            arg_list.extend(['--os-project-name',
                             CONF.keymanager.project_name])
            # NOTE(jaosorior): Should we add the user_domain_name to the
            #                  config?
            arg_list.extend(
                ['--os-user-domain-name', CONF.keymanager.project_domain_name])
            arg_list.extend(
                ['--os-project-domain-name',
                 CONF.keymanager.project_domain_name])
            arg_list.extend(['--os-identity-api-version', '3'])
        else:
            arg_list.extend(['--os-tenant-name', CONF.keymanager.project_name])
            arg_list.extend(['--os-identity-api-version', '2.0'])

        arg_list.extend(['--os-auth-url', CONF.identity.uri])
        arg_list.extend(['--os-username', CONF.keymanager.username,
                         '--os-password', CONF.keymanager.password])

        arg_list.extend(['--endpoint', CONF.keymanager.url])
        self.LOG.info('updated command string: %s', arg_list)

    def issue_barbican_command(self, argv):
        """Issue the barbican command and return its output.

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

    def _prettytable_to_dict(self, str):
        """Create a dict from the values in a PrettyTable string.

        :param str: a string representing a PrettyTable output from a
        barbican secret store or get command.
        :return: a dict containing the fields and values from the output.
        """
        retval = {}
        if str is not None and len(str) > 0:
            table_body = re.split('\+-*\+-*\+\n', str)[2:-1]
            lines = table_body[0].split('\n')
            for line in lines:
                if len(line) > 0:
                    row = line.split('|')
                    key = row[1].strip()
                    value = row[2].strip()
                    retval[key] = value
        return retval

    def _prettytable_to_list(self, str):
        """Create a list from the values in a PrettyTable string.

        :param str: a string representing a PrettyTable output from a
        barbican secret list command.
        :return: a list containing one dict for each column in the table.
        If there are no entries then an empty list will be returned.
        """
        retval = []
        if str is not None and len(str) > 0:
            rows = re.findall('\|(.*?)\n', str)
            # Remove header
            header_row = rows.pop(0)
            key_names = re.findall('\s*(.*?)\s*\|', header_row)
            for row in rows:
                values = re.findall('\s*(.*?)\s*\|', row)
                entry_dict = dict(zip(key_names, values))
                retval.append(entry_dict)
        return retval
