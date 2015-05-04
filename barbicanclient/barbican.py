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

"""
Command-line interface to the Barbican API.
"""

import sys

from cliff import app
from cliff import commandmanager
from keystoneclient.auth.identity import v3
from keystoneclient.auth.identity import v2
from keystoneclient import session
import six

from barbicanclient import client
from barbicanclient import version


_DEFAULT_IDENTITY_API_VERSION = '3.0'


class Barbican(app.App):
    """Barbican command line interface."""

    def __init__(self, **kwargs):
        super(Barbican, self).__init__(
            description=__doc__.strip(),
            version=version.__version__,
            command_manager=commandmanager.CommandManager('barbican.client'),
            **kwargs
        )

    def check_auth_arguments(self, args, api_version=None, raise_exc=False):
        """Verifies that we have the correct arguments for authentication

        Supported Keystone v3 combinations:
            - Project Id
            - Project Name + Project Domain Name
            - Project Name + Project Domain Id
        Supported Keystone v2 combinations:
            - Tenant Id
            - Tenant Name
        """
        successful = True
        v3_arg_combinations = [
            args.os_project_id,
            args.os_project_name and args.os_project_domain_name,
            args.os_project_name and args.os_project_domain_id
        ]
        v2_arg_combinations = [args.os_tenant_id, args.os_tenant_name]

        # Keystone V3
        if not api_version or api_version == _DEFAULT_IDENTITY_API_VERSION:
            if not any(v3_arg_combinations):
                msg = ('ERROR: please specify the following --os-project-id or'
                       ' (--os-project-name and --os-project-domain-name) or '
                       ' (--os-project-name and --os-project-domain-id)')
                successful = False
        # Keystone V2
        else:
            if not any(v2_arg_combinations):
                msg = ('ERROR: please specify --os-tenant-id or'
                       '--os-tenant-name')
                successful = False

        if not successful and raise_exc:
            raise Exception(msg)

        return successful

    def build_kwargs_based_on_version(self, args, api_version=None):
        if not api_version or api_version == _DEFAULT_IDENTITY_API_VERSION:
            kwargs = {
                'project_id': args.os_project_id,
                'project_name': args.os_project_name,
                'user_domain_id': args.os_user_domain_id,
                'user_domain_name': args.os_user_domain_name,
                'project_domain_id': args.os_project_domain_id,
                'project_domain_name': args.os_project_domain_name
            }
        else:
            kwargs = {
                'tenant_name': args.os_tenant_name,
                'tenant_id': args.os_tenant_id
            }

        # Return a dictionary with only the populated (not None) values
        return dict((k, v) for (k, v) in six.iteritems(kwargs) if v)

    def create_keystone_session(
            self, args, api_version, kwargs_dict, auth_type
    ):
        # Make sure we have the correct arguments to function
        self.check_auth_arguments(args, api_version, raise_exc=True)

        kwargs = self.build_kwargs_based_on_version(args, api_version)
        kwargs.update(kwargs_dict)

        if not api_version or api_version == _DEFAULT_IDENTITY_API_VERSION:
            method = v3.Token if auth_type == 'token' else v3.Password
        else:
            method = v2.Token if auth_type == 'token' else v2.Password

        auth = method(**kwargs)

        return session.Session(auth=auth, verify=not args.insecure)

    def create_client(self, args):
        created_client = None

        api_version = args.os_identity_api_version
        if args.no_auth and args.os_auth_url:
            raise Exception(
                'ERROR: argument --os-auth-url/-A: not allowed '
                'with argument --no-auth/-N'
            )

        if args.no_auth:
            if not all([args.endpoint, args.os_tenant_id or
                        args.os_project_id]):
                raise Exception(
                    'ERROR: please specify --endpoint and '
                    '--os-project-id (or --os-tenant-id)')
            created_client = client.Client(
                endpoint=args.endpoint,
                project_id=args.os_tenant_id or args.os_project_id,
                verify=not args.insecure
            )
        # Token-based authentication
        elif args.os_auth_token:
            if not args.os_auth_url:
                raise Exception('ERROR: please specify --os-auth-url')
            token_kwargs = {
                'auth_url': args.os_auth_url,
                'token': args.os_auth_token
            }
            session = self.create_keystone_session(
                args, api_version, token_kwargs, auth_type='token'
            )
            created_client = client.Client(
                session=session,
                endpoint=args.endpoint
            )

        # Password-based authentication
        elif args.os_auth_url:
            password_kwargs = {
                'auth_url': args.os_auth_url,
                'password': args.os_password,
                'user_id': args.os_user_id,
                'username': args.os_username
            }
            session = self.create_keystone_session(
                args, api_version, password_kwargs, auth_type='password'
            )
            created_client = client.Client(
                session=session,
                endpoint=args.endpoint
            )
        else:
            raise Exception('ERROR: please specify authentication credentials')

        return created_client

    def build_option_parser(self, description, version, argparse_kwargs=None):
        """Introduces global arguments for the application.
        This is inherited from the framework.
        """
        parser = super(Barbican, self).build_option_parser(
            description, version, argparse_kwargs)
        parser.add_argument('--no-auth', '-N', action='store_true',
                            help='Do not use authentication.')
        parser.add_argument('--os-identity-api-version',
                            metavar='<identity-api-version>',
                            default=client.env('OS_IDENTITY_API_VERSION'),
                            help='Specify Identity API version to use. '
                            'Defaults to env[OS_IDENTITY_API_VERSION]'
                            ' or 3.0.')
        parser.add_argument('--os-auth-url', '-A',
                            metavar='<auth-url>',
                            default=client.env('OS_AUTH_URL'),
                            help='Defaults to env[OS_AUTH_URL].')
        parser.add_argument('--os-username', '-U',
                            metavar='<auth-user-name>',
                            default=client.env('OS_USERNAME'),
                            help='Defaults to env[OS_USERNAME].')
        parser.add_argument('--os-user-id',
                            metavar='<auth-user-id>',
                            default=client.env('OS_USER_ID'),
                            help='Defaults to env[OS_USER_ID].')
        parser.add_argument('--os-password', '-P',
                            metavar='<auth-password>',
                            default=client.env('OS_PASSWORD'),
                            help='Defaults to env[OS_PASSWORD].')
        parser.add_argument('--os-user-domain-id',
                            metavar='<auth-user-domain-id>',
                            default=client.env('OS_USER_DOMAIN_ID'),
                            help='Defaults to env[OS_USER_DOMAIN_ID].')
        parser.add_argument('--os-user-domain-name',
                            metavar='<auth-user-domain-name>',
                            default=client.env('OS_USER_DOMAIN_NAME'),
                            help='Defaults to env[OS_USER_DOMAIN_NAME].')
        parser.add_argument('--os-tenant-name', '-T',
                            metavar='<auth-tenant-name>',
                            default=client.env('OS_TENANT_NAME'),
                            help='Defaults to env[OS_TENANT_NAME].')
        parser.add_argument('--os-tenant-id', '-I',
                            metavar='<tenant-id>',
                            default=client.env('OS_TENANT_ID'),
                            help='Defaults to env[OS_TENANT_ID].')
        parser.add_argument('--os-project-id',
                            metavar='<auth-project-id>',
                            default=client.env('OS_PROJECT__ID'),
                            help='Another way to specify tenant ID. '
                                 'This option is mutually exclusive with '
                                 ' --os-tenant-id. '
                            'Defaults to env[OS_PROJECT_ID].')
        parser.add_argument('--os-project-name',
                            metavar='<auth-project-name>',
                            default=client.env('OS_PROJECT_NAME'),
                            help='Another way to specify tenant name. '
                                 'This option is mutually exclusive with '
                                 ' --os-tenant-name. '
                                 'Defaults to env[OS_PROJECT_NAME].')
        parser.add_argument('--os-project-domain-id',
                            metavar='<auth-project-domain-id>',
                            default=client.env('OS_PROJECT_DOMAIN_ID'),
                            help='Defaults to env[OS_PROJECT_DOMAIN_ID].')
        parser.add_argument('--os-project-domain-name',
                            metavar='<auth-project-domain-name>',
                            default=client.env('OS_PROJECT_DOMAIN_NAME'),
                            help='Defaults to env[OS_PROJECT_DOMAIN_NAME].')
        parser.add_argument('--os-auth-token',
                            metavar='<auth-token>',
                            default=client.env('OS_AUTH_TOKEN'),
                            help='Defaults to env[OS_AUTH_TOKEN].')
        parser.add_argument('--endpoint', '-E',
                            metavar='<barbican-url>',
                            default=client.env('BARBICAN_ENDPOINT'),
                            help='Defaults to env[BARBICAN_ENDPOINT].')
        session.Session.register_cli_options(parser)
        return parser

    def initialize_app(self, argv):
        """Initializes the application.
        Checks if the minimal parameters are provided and creates the client
        interface.
        This is inherited from the framework.
        """
        args = self.options
        self.client = self.create_client(args)

    def run(self, argv):
        # If no arguments are provided, usage is displayed
        if not argv:
            self.stderr.write(self.parser.format_usage())
            return 1
        return super(Barbican, self).run(argv)


def main(argv=sys.argv[1:]):
    barbican_app = Barbican()
    return barbican_app.run(argv)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
