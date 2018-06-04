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
Command-line interface sub-commands related to secrets.
"""
import os

from cliff import command
from cliff import lister
from cliff import show

from barbicanclient import secrets


class DeleteSecret(command.Command):
    """Delete a secret by providing its URI."""

    def get_parser(self, prog_name):
        parser = super(DeleteSecret, self).get_parser(prog_name)
        parser.add_argument('URI', help='The URI reference for the secret')
        return parser

    def take_action(self, args):
        self.app.client_manager.key_manager.secrets.delete(args.URI)


class GetSecret(show.ShowOne):
    """Retrieve a secret by providing its URI."""

    def get_parser(self, prog_name):
        parser = super(GetSecret, self).get_parser(prog_name)
        parser.add_argument('URI', help='The URI reference for the secret.')
        payload_params = parser.add_mutually_exclusive_group(required=False)
        payload_params.add_argument('--decrypt', '-d',
                                    help='if specified, retrieve the '
                                    'unencrypted secret data.',
                                    action='store_true')
        payload_params.add_argument('--payload', '-p',
                                    help='if specified, retrieve the '
                                    'unencrypted secret data.',
                                    action='store_true')
        payload_params.add_argument('--file', '-F', metavar='<filename>',
                                    help='if specified, save the payload to a '
                                         'new file with the given filename.')
        parser.add_argument('--payload_content_type', '-t',
                            default='text/plain',
                            help='the content type of the decrypted'
                                 ' secret (default: %(default)s).')
        return parser

    def take_action(self, args):
        if args.decrypt or args.payload or args.file:
            entity = self.app.client_manager.key_manager.secrets.get(
                args.URI, args.payload_content_type)
            return (('Payload',),
                    (entity.payload,))
        else:
            entity = self.app.client_manager.key_manager.secrets.get(
                secret_ref=args.URI)
            return entity._get_formatted_entity()

    def produce_output(self, parsed_args, column_names, data):
        if parsed_args.file:
            if os.path.exists(parsed_args.file):
                raise ValueError("ERROR: file already exists.")
            with open(parsed_args.file, 'wb') as f:
                f.write(data[0])

        else:
            super(GetSecret, self).produce_output(
                parsed_args, column_names, data
            )


class UpdateSecret(command.Command):
    """Update a secret with no payload in Barbican."""

    def get_parser(self, prog_name):
        parser = super(UpdateSecret, self).get_parser(prog_name)
        parser.add_argument('URI', help='The URI reference for the secret.')
        parser.add_argument('payload', help='the unencrypted secret')

        return parser

    def take_action(self, args):
        self.app.client_manager.key_manager.secrets.update(args.URI,
                                                           args.payload)


class ListSecret(lister.Lister):
    """List secrets."""

    def get_parser(self, prog_name):
        parser = super(ListSecret, self).get_parser(prog_name)
        parser.add_argument('--limit', '-l', default=10,
                            help='specify the limit to the number of items '
                                 'to list per page (default: %(default)s; '
                                 'maximum: 100)',
                            type=int)
        parser.add_argument('--offset', '-o', default=0,
                            help='specify the page offset '
                                 '(default: %(default)s)',
                            type=int)
        parser.add_argument('--name', '-n', default=None,
                            help='specify the secret name '
                                 '(default: %(default)s)')
        parser.add_argument('--algorithm', '-a', default=None,
                            help='the algorithm filter for the list'
                                 '(default: %(default)s).')
        parser.add_argument('--bit-length', '-b', default=0,
                            help='the bit length filter for the list'
                                 ' (default: %(default)s).',
                            type=int)
        parser.add_argument('--mode', '-m', default=None,
                            help='the algorithm mode filter for the'
                                 ' list (default: %(default)s).')
        parser.add_argument('--secret-type', '-s', default=None,
                            help='specify the secret type '
                                 '(default: %(default)s).')
        return parser

    def take_action(self, args):
        obj_list = self.app.client_manager.key_manager.secrets.list(
            limit=args.limit, offset=args.offset, name=args.name,
            algorithm=args.algorithm, mode=args.mode, bits=args.bit_length,
            secret_type=args.secret_type)
        return secrets.Secret._list_objects(obj_list)


class StoreSecret(show.ShowOne):
    """Store a secret in Barbican."""

    def get_parser(self, prog_name):
        parser = super(StoreSecret, self).get_parser(prog_name)
        parser.add_argument('--name', '-n',
                            help='a human-friendly name.')
        parser.add_argument('--secret-type', '-s', default='opaque',
                            help='the secret type; must be one of symmetric, '
                                 'public, private, certificate, passphrase, '
                                 'opaque (default)')
        parser.add_argument('--payload-content-type', '-t',
                            help='the type/format of the provided '
                                 'secret data; "text/plain" is assumed to be '
                                 'UTF-8; required when --payload is '
                                 'supplied.')
        parser.add_argument('--payload-content-encoding', '-e',
                            help='required if --payload-content-type is '
                                 '"application/octet-stream".')
        parser.add_argument('--algorithm', '-a', default='aes',
                            help='the algorithm (default: '
                                 '%(default)s).')
        parser.add_argument('--bit-length', '-b', default=256,
                            help='the bit length '
                                 '(default: %(default)s).',
                            type=int)
        parser.add_argument('--mode', '-m', default='cbc',
                            help='the algorithm mode; used only for '
                                 'reference (default: %(default)s)')
        parser.add_argument('--expiration', '-x',
                            help='the expiration time for the secret in '
                                 'ISO 8601 format.')
        payload_params = parser.add_mutually_exclusive_group(required=False)
        payload_params.add_argument('--payload', '-p',
                                    help='the unencrypted secret data.')
        payload_params.add_argument('--file', '-F', metavar='<filename>',
                                    help='file containing the secret payload')
        return parser

    def take_action(self, args):
        data = None
        if args.file:
            with open(args.file, 'rb') as f:
                data = f.read()

        entity = self.app.client_manager.key_manager.secrets.create(
            name=args.name, payload=args.payload or data,
            payload_content_type=args.payload_content_type,
            payload_content_encoding=args.payload_content_encoding,
            algorithm=args.algorithm, bit_length=args.bit_length,
            mode=args.mode, expiration=args.expiration,
            secret_type=args.secret_type)
        entity.store()
        return entity._get_formatted_entity()
