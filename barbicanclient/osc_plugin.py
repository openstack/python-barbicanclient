#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

"""OpenStackClient plugin for Key Manager service."""

from barbicanclient import client


DEFAULT_API_VERSION = '1'
API_VERSION_OPTION = 'os_key_manager_api_version'
API_NAME = 'key_manager'
API_VERSIONS = {
    '1': 'barbicanclient.client.Client',
}


def make_client(instance):
    """Returns a Barbican service client."""
    return client.Client(session=instance.session,
                         region_name=instance._region_name,
                         interface=instance.interface)


def build_option_parser(parser):
    """Hook to add global options."""
    parser.add_argument('--os-key-manager-api-version',
                        metavar='<key-manager-api-version>',
                        default=client.env(
                            'OS_KEY_MANAGER_API_VERSION',
                            default=DEFAULT_API_VERSION),
                        help=('Barbican API version, default=' +
                              DEFAULT_API_VERSION +
                              ' (Env: OS_KEY_MANAGER_API_VERSION)'))
    return parser
