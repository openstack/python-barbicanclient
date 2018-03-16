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

from collections import namedtuple
import logging
import sys

from cliff import app
from cliff import command
from cliff import commandmanager
from cliff import complete
from cliff import help
from keystoneauth1 import identity
from keystoneauth1 import loading
from keystoneauth1 import session

import barbicanclient
from barbicanclient._i18n import _LW
from barbicanclient import client


LOG = logging.getLogger(__name__)


_DEFAULT_IDENTITY_API_VERSION = '3'
_IDENTITY_API_VERSION_2 = ['2', '2.0']
_IDENTITY_API_VERSION_3 = ['3']


class Barbican(app.App):
    """Barbican command line interface."""

    # verbose logging levels
    WARNING_LEVEL = 0
    INFO_LEVEL = 1
    DEBUG_LEVEL = 2
    CONSOLE_MESSAGE_FORMAT = '%(message)s'
    DEBUG_MESSAGE_FORMAT = '%(levelname)s: %(name)s %(message)s'

    def __init__(self, **kwargs):
        self.client = None

        # Patch command.Command to add a default auth_required = True
        command.Command.auth_required = True

        # Some commands do not need authentication
        help.HelpCommand.auth_required = False
        complete.CompleteCommand.auth_required = False

        super(Barbican, self).__init__(
            description=__doc__.strip(),
            version=barbicanclient.__version__,
            command_manager=commandmanager.CommandManager(
                'openstack.key_manager.v1'),
            deferred_help=True,
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
                       ' --os-tenant-name')
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
        return dict((k, v) for (k, v) in kwargs.items() if v)

    def create_keystone_session(
            self, args, api_version, kwargs_dict, auth_type
    ):
        # Make sure we have the correct arguments to function
        self.check_auth_arguments(args, api_version, raise_exc=True)

        kwargs = self.build_kwargs_based_on_version(args, api_version)
        kwargs.update(kwargs_dict)

        _supported_version = _IDENTITY_API_VERSION_2 + _IDENTITY_API_VERSION_3
        if not api_version or api_version not in _supported_version:
            self.stderr.write(
                "WARNING: The identity version <{0}> is not in supported "
                "versions <{1}>, falling back to <{2}>.".format(
                    api_version,
                    _IDENTITY_API_VERSION_2 + _IDENTITY_API_VERSION_3,
                    _DEFAULT_IDENTITY_API_VERSION
                )
            )
        method = identity.Token if auth_type == 'token' else identity.Password

        auth = method(**kwargs)

        return session.Session(auth=auth, verify=not args.insecure)

    def create_client(self, args):
        created_client = None
        endpoint_filter_kwargs = self._get_endpoint_filter_kwargs(args)

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
                verify=not args.insecure,
                **endpoint_filter_kwargs
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
                endpoint=args.endpoint,
                **endpoint_filter_kwargs
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
                endpoint=args.endpoint,
                **endpoint_filter_kwargs
            )
        else:
            raise Exception('ERROR: please specify authentication credentials')

        return created_client

    def _get_endpoint_filter_kwargs(self, args):
        endpoint_filter_keys = ('interface', 'service_type', 'service_name',
                                'barbican_api_version', 'region_name')
        kwargs = dict((key, getattr(args, key)) for key in endpoint_filter_keys
                      if getattr(args, key, None))
        if 'barbican_api_version' in kwargs:
            kwargs['version'] = kwargs.pop('barbican_api_version')
        return kwargs

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
                            ' or 3.')
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
                            default=client.env('OS_PROJECT_ID'),
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
        parser.add_argument('--interface',
                            metavar='<barbican-interface>',
                            default=client.env('BARBICAN_INTERFACE'),
                            help='Defaults to env[BARBICAN_INTERFACE].')
        parser.add_argument('--service-type',
                            metavar='<barbican-service-type>',
                            default=client.env('BARBICAN_SERVICE_TYPE'),
                            help='Defaults to env[BARBICAN_SERVICE_TYPE].')
        parser.add_argument('--service-name',
                            metavar='<barbican-service-name>',
                            default=client.env('BARBICAN_SERVICE_NAME'),
                            help='Defaults to env[BARBICAN_SERVICE_NAME].')
        parser.add_argument('--region-name',
                            metavar='<barbican-region-name>',
                            default=client.env('BARBICAN_REGION_NAME'),
                            help='Defaults to env[BARBICAN_REGION_NAME].')
        parser.add_argument('--barbican-api-version',
                            metavar='<barbican-api-version>',
                            default=client.env('BARBICAN_API_VERSION'),
                            help='Defaults to env[BARBICAN_API_VERSION].')
        parser.epilog = ('See "barbican help COMMAND" for help '
                         'on a specific command.')
        loading.register_session_argparse_arguments(parser)
        return parser

    def prepare_to_run_command(self, cmd):
        """Prepares to run the command

        Checks if the minimal parameters are provided and creates the
        client interface.
        This is inherited from the framework.
        """
        self.client_manager = namedtuple('ClientManager', 'key_manager')
        if cmd.auth_required:
            # NOTE(liujiong): cliff sets log level to DEBUG in run function,
            # need to overwrite this configuration to depress DEBUG messages.
            self.configure_logging()
            self.client_manager.key_manager = self.create_client(self.options)

    def run(self, argv):
        # If no arguments are provided, usage is displayed
        if not argv:
            self.stderr.write(self.parser.format_usage())
            return 1
        return super(Barbican, self).run(argv)

    def configure_logging(self):
        """Create logging handlers for any log output."""
        root_logger = logging.getLogger('')
        # Set log level to INFO
        root_logger.setLevel(logging.INFO)

        # Send higher-level messages to the console via stderr
        console = logging.StreamHandler(self.stderr)
        console_level = {self.WARNING_LEVEL: logging.WARNING,
                         self.INFO_LEVEL: logging.INFO,
                         self.DEBUG_LEVEL: logging.DEBUG,
                         }.get(self.options.verbose_level, logging.INFO)
        if logging.DEBUG == console_level:
            formatter = logging.Formatter(self.DEBUG_MESSAGE_FORMAT)
        else:
            formatter = logging.Formatter(self.CONSOLE_MESSAGE_FORMAT)
        console.setFormatter(formatter)
        root_logger.addHandler(console)
        return


def main(argv=sys.argv[1:]):
    logging.basicConfig()
    LOG.warning(_LW("This Barbican CLI interface has been deprecated and "
                    "will be removed in the O release. Please use the "
                    "openstack unified client instead."))
    barbican_app = Barbican()
    return barbican_app.run(argv)

if __name__ == '__main__':   # pragma: no cover
    sys.exit(main(sys.argv[1:]))
