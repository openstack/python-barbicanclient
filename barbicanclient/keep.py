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
import argparse

from barbicanclient.common import auth
from barbicanclient import client


class Keep:
    def __init__(self):
        self.parser = self._get_main_parser()
        self.subparsers = self.parser.add_subparsers(
            title='subcommands',
            metavar='<action>',
            description='Action to perform'
        )
        self._add_create_args()
        self._add_store_args()
        self._add_get_args()
        self._add_list_args()
        self._add_delete_args()

    def _get_main_parser(self):
        parser = argparse.ArgumentParser(
            description=__doc__.strip()
        )
        parser.add_argument('command',
                            metavar='<entity>',
                            choices=['order', 'secret'],
                            help='Entity used for command, e.g.,'
                                 ' order, secret.')
        auth_group = parser.add_mutually_exclusive_group()
        auth_group.add_argument('--no-auth', '-N', action='store_true',
                                help='Do not use authentication.')
        auth_group.add_argument('--os-auth-url', '-A',
                                metavar='<auth-url>',
                                default=client.env('OS_AUTH_URL'),
                                help='Defaults to env[OS_AUTH_URL].')
        parser.add_argument('--os-username', '-U',
                            metavar='<auth-user-name>',
                            default=client.env('OS_USERNAME'),
                            help='Defaults to env[OS_USERNAME].')
        parser.add_argument('--os-password', '-P',
                            metavar='<auth-password>',
                            default=client.env('OS_PASSWORD'),
                            help='Defaults to env[OS_PASSWORD].')
        parser.add_argument('--os-tenant-name', '-T',
                            metavar='<auth-tenant-name>',
                            default=client.env('OS_TENANT_NAME'),
                            help='Defaults to env[OS_TENANT_NAME].')
        parser.add_argument('--os-tenant-id', '-I',
                            metavar='<tenant-id>',
                            default=client.env('OS_TENANT_ID'),
                            help='Defaults to env[OS_TENANT_ID].')
        parser.add_argument('--endpoint', '-E',
                            metavar='<barbican-url>',
                            default=client.env('BARBICAN_ENDPOINT'),
                            help='Defaults to env[BARBICAN_ENDPOINT].')
        return parser

    def _add_create_args(self):
        create_parser = self.subparsers.add_parser('create',
                                                   help='Create a new order.')
        create_parser.add_argument('--name', '-n',
                                   help='a human-friendly name.')
        create_parser.add_argument('--algorithm', '-a', default='aes',
                                   help='the algorithm to be used with the '
                                        'requested key (default: '
                                        '%(default)s).')
        create_parser.add_argument('--bit-length', '-b', default=256,
                                   help='the bit length of the requested'
                                        ' secret key (default: %(default)s).',
                                   type=int)
        create_parser.add_argument('--mode', '-m', default='cbc',
                                   help='the algorithmm mode to be used with '
                                   'the rquested key (default: %(default)s).')
        create_parser.add_argument('--payload-content-type', '-t',
                                   default='application/octet-stream',
                                   help='the type/format of the secret to be'
                                        ' generated (default: %(default)s).')
        create_parser.add_argument('--expiration', '-x', help='the expiration '
                                   'time for the secret in ISO 8601 format.')
        create_parser.set_defaults(func=self.create)

    def _add_store_args(self):
        store_parser = self.subparsers.add_parser(
            'store',
            help='Store a secret in barbican.'
        )
        store_parser.add_argument('--name', '-n',
                                  help='a human-friendly name.')
        store_parser.add_argument('--payload', '-p', help='the unencrypted'
                                  ' secret; if provided, you must also provide'
                                  ' a payload_content_type')
        store_parser.add_argument('--payload-content-type', '-t',
                                  help='the type/format of the provided '
                                  'secret data; "text/plain" is assumed to be'
                                  ' UTF-8; required when --payload is'
                                  ' supplied.')
        store_parser.add_argument('--payload-content-encoding', '-e',
                                  help='required if --payload-content-type is'
                                  ' "application/octet-stream".')
        store_parser.add_argument('--algorithm', '-a', default='aes',
                                  help='the algorithm (default: %(default)s).')
        store_parser.add_argument('--bit-length', '-b', default=256,
                                  help='the bit length '
                                       '(default: %(default)s).',
                                  type=int)
        store_parser.add_argument('--mode', '-m', default='cbc',
                                  help='the algorithmm mode; used only for '
                                  'reference (default: %(default)s)')
        store_parser.add_argument('--expiration', '-x', help='the expiration '
                                  'time for the secret in ISO 8601 format.')
        store_parser.set_defaults(func=self.store)

    def _add_delete_args(self):
        delete_parser = self.subparsers.add_parser(
            'delete',
            help='Delete a secret or an order by providing its href.'
        )
        delete_parser.add_argument('URI', help='The URI reference for the'
                                               ' secret or order')
        delete_parser.set_defaults(func=self.delete)

    def _add_get_args(self):
        get_parser = self.subparsers.add_parser(
            'get',
            help='Retrieve a secret or an order by providing its URI.'
        )
        get_parser.add_argument('URI', help='The URI reference for the secret'
                                ' or order.')
        get_parser.add_argument('--decrypt', '-d', help='if specified, keep'
                                ' will retrieve the unencrypted secret data;'
                                ' the data type can be specified with'
                                ' --payload-content-type (only used for'
                                ' secrets).',
                                action='store_true')
        get_parser.add_argument('--payload_content_type', '-t',
                                default='text/plain',
                                help='the content type of the decrypted'
                                ' secret (default: %(default)s; only used for'
                                ' secrets)')
        get_parser.set_defaults(func=self.get)

    def _add_list_args(self):
        list_parser = self.subparsers.add_parser('list',
                                                 help='List secrets or orders')
        list_parser.add_argument('--limit', '-l', default=10, help='specify t'
                                 'he limit to the number of items to list per'
                                 ' page (default: %(default)s; maximum: 100)',
                                 type=int)
        list_parser.add_argument('--offset', '-o', default=0, help='specify t'
                                 'he page offset (default: %(default)s)',
                                 type=int)
        list_parser.set_defaults(func=self.list)

    def store(self, args):
        if args.command == 'secret':
            secret = self.client.secrets.store(args.name,
                                               args.payload,
                                               args.payload_content_type,
                                               args.payload_content_encoding,
                                               args.algorithm,
                                               args.bit_length,
                                               args.mode,
                                               args.expiration)
            print secret
        else:
            self.parser.exit(status=1, message='ERROR: store is only supported'
                                               ' for secrets\n')

    def create(self, args):
        if args.command == 'order':
            order = self.client.orders.create(args.name,
                                              args.payload_content_type,
                                              args.algorithm,
                                              args.bit_length,
                                              args.mode,
                                              args.expiration)
            print order
        else:
            self.parser.exit(status=1, message='ERROR: create is only '
                                               'supported for orders\n')

    def delete(self, args):
        if args.command == 'secret':
            self.client.secret.delete(args.URI)
        else:
            self.client.orders.delete(args.URI)

    def get(self, args):
        if args.command == 'secret':
            if args.decrypt:
                print self.client.secrets.raw(args.URI,
                                              args.payload_content_type)
            else:
                print self.client.secrets.get(args.URI)
        else:
            print self.client.orders.get(args.URI)

    def list(self, args):
        if args.command == 'secret':
            ls = self.client.secrets.list(args.limit, args.offset)
        else:
            ls = self.client.orders.list(args.limit, args.offset)
        for obj in ls:
            print obj
        print '{0}s displayed: {1} - offset: {2}'.format(args.command, len(ls),
                                                         args.offset)

    def execute(self, **kwargs):
        args = self.parser.parse_args(kwargs.get('argv'))
        if args.no_auth:
            self.client = client.Client(endpoint=args.endpoint,
                                        tenant_id=args.os_tenant_id)
        elif all([args.os_auth_url, args.os_username, args.os_password,
                  args.os_tenant_name]):
            self._keystone = auth.KeystoneAuthV2(
                auth_url=args.os_auth_url,
                username=args.os_username,
                password=args.os_password,
                tenant_name=args.os_tenant_name
            )
            self.client = client.Client(auth_plugin=self._keystone,
                                        endpoint=args.endpoint,
                                        tenant_id=args.tenant_id)
        else:
            self.parser.exit(
                status=1,
                message='ERROR: please specify authentication credentials\n'
            )
        args.func(args)


def main():
    k = Keep()
    k.execute()


if __name__ == '__main__':
    main()
