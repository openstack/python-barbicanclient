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
Command-line interface sub-commands related to orders.
"""

from cliff import command
from cliff import lister
from cliff import show

from barbicanclient.barbican_cli.formatter import EntityFormatter


class OrderFormatter(EntityFormatter):

    columns = ("Order href",
               "Secret href",
               "Created",
               "Status",
               )

    def _get_formatted_data(self, entity):
        data = (entity.order_ref,
                entity.secret_ref,
                entity.created,
                entity.status,
                )
        return data


class CreateOrder(show.ShowOne, OrderFormatter):
    """Create a new order."""

    def get_parser(self, prog_name):
        parser = super(CreateOrder, self).get_parser(prog_name)
        parser.add_argument('--name', '-n',
                            help='a human-friendly name.')
        parser.add_argument('--algorithm', '-a', default='aes',
                            help='the algorithm to be used with the '
                                 'requested key (default: '
                                 '%(default)s).')
        parser.add_argument('--bit-length', '-b', default=256,
                            help='the bit length of the requested'
                                 ' secret key (default: %(default)s).',
                            type=int)
        parser.add_argument('--mode', '-m', default='cbc',
                            help='the algorithm mode to be used with '
                                 'the requested key (default: %(default)s).')
        parser.add_argument('--payload-content-type', '-t',
                            default='application/octet-stream',
                            help='the type/format of the secret to be'
                                 ' generated (default: %(default)s).')
        parser.add_argument('--expiration', '-x',
                            help='the expiration '
                                 'time for the secret in ISO 8601 format.')
        return parser

    def take_action(self, args):
        entity = self.app.client.orders.create(args.name,
                                               args.payload_content_type,
                                               args.algorithm,
                                               args.bit_length,
                                               args.mode,
                                               args.expiration)
        return self._get_formatted_entity(entity)


class DeleteOrder(command.Command):
    """Delete an order by providing its href."""

    def get_parser(self, prog_name):
        parser = super(DeleteOrder, self).get_parser(prog_name)
        parser.add_argument('URI', help='The URI reference for the order')
        return parser

    def take_action(self, args):
        self.app.client.orders.delete(args.URI)


class GetOrder(show.ShowOne, OrderFormatter):
    """Retrieve an order by providing its URI."""

    def get_parser(self, prog_name):
        parser = super(GetOrder, self).get_parser(prog_name)
        parser.add_argument('URI', help='The URI reference order.')
        return parser

    def take_action(self, args):
        entity = self.app.client.orders.get(args.URI)
        return self._get_formatted_entity(entity)


class ListOrder(lister.Lister, OrderFormatter):
    """List orders."""

    def get_parser(self, prog_name):
        parser = super(ListOrder, self).get_parser(prog_name)
        parser.add_argument('--limit', '-l', default=10,
                            help='specify the limit to the number of items '
                                 'to list per page (default: %(default)s; '
                                 'maximum: 100)',
                            type=int)
        parser.add_argument('--offset', '-o', default=0,
                            help='specify the page offset '
                                 '(default: %(default)s)',
                            type=int)
        return parser

    def take_action(self, args):
        obj_list = self.app.client.orders.list(args.limit, args.offset)
        return self._list_objects(obj_list)
