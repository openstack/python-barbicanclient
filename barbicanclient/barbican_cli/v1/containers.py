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
Command-line interface sub-commands related to containers.
"""
from cliff import command
from cliff import lister
from cliff import show

from barbicanclient.v1.containers import CertificateContainer
from barbicanclient.v1.containers import Container
from barbicanclient.v1.containers import RSAContainer


class DeleteContainer(command.Command):
    """Delete a container by providing its href."""

    def get_parser(self, prog_name):
        parser = super(DeleteContainer, self).get_parser(prog_name)
        parser.add_argument('URI', help='The URI reference for the container')
        return parser

    def take_action(self, args):
        self.app.client_manager.key_manager.containers.delete(args.URI)


class GetContainer(show.ShowOne):
    """Retrieve a container by providing its URI."""

    def get_parser(self, prog_name):
        parser = super(GetContainer, self).get_parser(prog_name)
        parser.add_argument('URI', help='The URI reference for the container.')
        return parser

    def take_action(self, args):
        entity = self.app.client_manager.key_manager.containers.get(
            args.URI)
        return entity._get_formatted_entity()


class ListContainer(lister.Lister):
    """List containers."""

    def get_parser(self, prog_name):
        parser = super(ListContainer, self).get_parser(prog_name)
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
                            help='specify the container name '
                                 '(default: %(default)s)')
        parser.add_argument('--type', '-t', default=None,
                            help='specify the type filter for the list '
                                 '(default: %(default)s).')
        return parser

    def take_action(self, args):
        obj_list = self.app.client_manager.key_manager.containers.list(
            args.limit, args.offset, args.name, args.type)
        return Container._list_objects(obj_list)


class CreateContainer(show.ShowOne):
    """Store a container in Barbican."""

    def get_parser(self, prog_name):
        parser = super(CreateContainer, self).get_parser(prog_name)
        parser.add_argument('--name', '-n',
                            help='a human-friendly name.')
        parser.add_argument('--type', default='generic',
                            help='type of container to create (default: '
                                 '%(default)s).')
        parser.add_argument('--secret', '-s', action='append',
                            help='one secret to store in a container '
                                 '(can be set multiple times). Example: '
                                 '--secret "private_key='
                                 'https://url.test/v1/secrets/1-2-3-4"')
        return parser

    def take_action(self, args):
        client = self.app.client_manager.key_manager
        container_type = client.containers._container_map.get(args.type)
        if not container_type:
            raise ValueError('Invalid container type specified.')
        secret_refs = CreateContainer._parse_secrets(args.secret)
        if container_type is RSAContainer:
            public_key_ref = secret_refs.get('public_key')
            private_key_ref = secret_refs.get('private_key')
            private_key_pass_ref = secret_refs.get('private_key_passphrase')
            entity = RSAContainer(
                api=client.containers._api,
                name=args.name,
                public_key_ref=public_key_ref,
                private_key_ref=private_key_ref,
                private_key_passphrase_ref=private_key_pass_ref,
            )
        elif container_type is CertificateContainer:
            certificate_ref = secret_refs.get('certificate')
            intermediates_ref = secret_refs.get('intermediates')
            private_key_ref = secret_refs.get('private_key')
            private_key_pass_ref = secret_refs.get('private_key_passphrase')
            entity = CertificateContainer(
                api=client.containers._api,
                name=args.name,
                certificate_ref=certificate_ref,
                intermediates_ref=intermediates_ref,
                private_key_ref=private_key_ref,
                private_key_passphrase_ref=private_key_pass_ref,
            )
        else:
            entity = container_type(api=client.containers._api,
                                    name=args.name, secret_refs=secret_refs)
        entity.store()
        return entity._get_formatted_entity()

    @staticmethod
    def _parse_secrets(secrets):
        if not secrets:
            raise ValueError("Must supply at least one secret.")
        return dict(
            (s.split('=')[0], s.split('=')[1])
            for s in secrets if s.count('=') == 1
        )
