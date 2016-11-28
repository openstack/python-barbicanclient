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
Command-line interface sub-commands related to cas.
"""
from cliff import lister
from cliff import show

from barbicanclient.v1 import cas


class GetCA(show.ShowOne):
    """Retrieve a CA by providing its URI."""

    def get_parser(self, prog_name):
        parser = super(GetCA, self).get_parser(prog_name)
        parser.add_argument('URI', help='The URI reference for the CA.')
        return parser

    def take_action(self, args):
        entity = self.app.client_manager.key_manager.cas.get(ca_ref=args.URI)
        return entity._get_formatted_entity()


class ListCA(lister.Lister):
    """List CAs."""

    def get_parser(self, prog_name):
        parser = super(ListCA, self).get_parser(prog_name)
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
                            help='specify the ca name '
                                 '(default: %(default)s)')
        return parser

    def take_action(self, args):
        obj_list = self.app.client_manager.key_manager.cas.list(
            args.limit, args.offset, args.name)
        return cas.CA._list_objects(obj_list)
