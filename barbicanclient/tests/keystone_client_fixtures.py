# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy

from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from requests_mock.contrib import fixture
import testtools

import barbicanclient.barbican

# these are copied from python-keystoneclient tests
BASE_HOST = 'http://keystone.example.com'
BASE_URL = "%s:5000/" % BASE_HOST
UPDATED = '2013-03-06T00:00:00Z'

V2_URL = "%sv2.0" % BASE_URL
V2_DESCRIBED_BY_HTML = {'href': 'http://docs.openstack.org/api/'
                                'openstack-identity-service/2.0/content/',
                        'rel': 'describedby',
                        'type': 'text/html'}
V2_DESCRIBED_BY_PDF = {'href': 'http://docs.openstack.org/api/openstack-ident'
                               'ity-service/2.0/identity-dev-guide-2.0.pdf',
                       'rel': 'describedby',
                       'type': 'application/pdf'}

V2_VERSION = {'id': 'v2.0',
              'links': [{'href': V2_URL, 'rel': 'self'},
                        V2_DESCRIBED_BY_HTML, V2_DESCRIBED_BY_PDF],
              'status': 'stable',
              'updated': UPDATED}

V3_URL = "%sv3" % BASE_URL
V3_MEDIA_TYPES = [{'base': 'application/json',
                   'type': 'application/vnd.openstack.identity-v3+json'},
                  {'base': 'application/xml',
                   'type': 'application/vnd.openstack.identity-v3+xml'}]

V3_VERSION = {'id': 'v3',
              'links': [{'href': V3_URL, 'rel': 'self'}],
              'media-types': V3_MEDIA_TYPES,
              'status': 'stable',
              'updated': UPDATED}


def _create_version_list(versions):
    return jsonutils.dumps({'versions': {'values': versions}})


def _create_single_version(version):
    return jsonutils.dumps({'version': version})


V3_VERSION_LIST = _create_version_list([V3_VERSION, V2_VERSION])
V2_VERSION_LIST = _create_version_list([V2_VERSION])

V3_VERSION_ENTRY = _create_single_version(V3_VERSION)
V2_VERSION_ENTRY = _create_single_version(V2_VERSION)

BARBICAN_ENDPOINT = 'http://www.barbican.com/v1'


def _get_normalized_token_data(**kwargs):
    ref = copy.deepcopy(kwargs)
    # normalized token data
    ref['user_id'] = ref.get('user_id',
                             uuidutils.generate_uuid(dashed=False))
    ref['username'] = ref.get('username',
                              uuidutils.generate_uuid(dashed=False))
    ref['project_id'] = ref.get(
        'project_id',
        ref.get('tenant_id', uuidutils.generate_uuid(dashed=False)))
    ref['project_name'] = ref.get(
        'tenant_name',
        ref.get('tenant_name', uuidutils.generate_uuid(dashed=False)))
    ref['user_domain_id'] = ref.get(
        'user_domain_id',
        uuidutils.generate_uuid(dashed=False))
    ref['user_domain_name'] = ref.get(
        'user_domain_name',
        uuidutils.generate_uuid(dashed=False))
    ref['project_domain_id'] = ref.get(
        'project_domain_id',
        uuidutils.generate_uuid(dashed=False))
    ref['project_domain_name'] = ref.get(
        'project_domain_name',
        uuidutils.generate_uuid(dashed=False))
    ref['roles'] = ref.get(
        'roles',
        [{'name': uuidutils.generate_uuid(dashed=False),
          'id': uuidutils.generate_uuid(dashed=False)}])
    ref['roles_link'] = ref.get('roles_link', [])
    ref['barbican_url'] = ref.get('barbican_url', BARBICAN_ENDPOINT)

    return ref


def generate_v2_project_scoped_token(**kwargs):
    """Generate a Keystone V2 token based on auth request."""
    ref = _get_normalized_token_data(**kwargs)

    o = {'access': {'token': {'id': uuidutils.generate_uuid(dashed=False),
                              'expires': '2099-05-22T00:02:43.941430Z',
                              'issued_at': '2013-05-21T00:02:43.941473Z',
                              'tenant': {'enabled': True,
                                         'id': ref.get('project_id'),
                                         'name': ref.get('project_id')
                                         }
                              },
                    'user': {'id': ref.get('user_id'),
                             'name':
                                 uuidutils.generate_uuid(dashed=False),
                             'username': ref.get('username'),
                             'roles': ref.get('roles'),
                             'roles_links': ref.get('roles_links')
                             }
                    }}

    # we only care about Barbican and Keystone endpoints
    o['access']['serviceCatalog'] = [
        {'endpoints': [
            {'publicURL': ref.get('barbican_url'),
             'id': uuidutils.generate_uuid(dashed=False),
             'region': 'RegionOne'
             }],
         'endpoints_links': [],
         'name': 'Barbican',
         'type': 'keystore'},
        {'endpoints': [
            {'publicURL': ref.get('auth_url'),
             'adminURL': ref.get('auth_url'),
             'id': uuidutils.generate_uuid(dashed=False),
             'region': 'RegionOne'
             }],
         'endpoint_links': [],
         'name': 'keystone',
         'type': 'identity'}]

    return o


def generate_v3_project_scoped_token(**kwargs):
    """Generate a Keystone V3 token based on auth request."""
    ref = _get_normalized_token_data(**kwargs)

    o = {'token': {'expires_at': '2099-05-22T00:02:43.941430Z',
                   'issued_at': '2013-05-21T00:02:43.941473Z',
                   'methods': ['password'],
                   'project': {'id': ref.get('project_id'),
                               'name': ref.get('project_name'),
                               'domain': {'id': ref.get('project_domain_id'),
                                          'name': ref.get(
                                              'project_domain_name')
                                          }
                               },
                   'user': {'id': ref.get('user_id'),
                            'name': ref.get('username'),
                            'domain': {'id': ref.get('user_domain_id'),
                                       'name': ref.get('user_domain_name')
                                       }
                            },
                   'roles': ref.get('roles')
                   }}

    # we only care about Barbican and Keystone endpoints
    o['token']['catalog'] = [
        {'endpoints': [
            {
                'id': uuidutils.generate_uuid(dashed=False),
                'interface': 'public',
                'region': 'RegionTwo',
                'url': ref.get('barbican_url')
            }],
         'id': uuidutils.generate_uuid(dashed=False),
         'type': 'keystore'},
        {'endpoints': [
            {
                'id': uuidutils.generate_uuid(dashed=False),
                'interface': 'public',
                'region': 'RegionTwo',
                'url': ref.get('auth_url')
            },
            {
                'id': uuidutils.generate_uuid(dashed=False),
                'interface': 'admin',
                'region': 'RegionTwo',
                'url': ref.get('auth_url')
            }],
         'id': uuidutils.generate_uuid(dashed=False),
         'type': 'identity'}]

    # token ID is conveyed via the X-Subject-Token header so we are generating
    # one to stash there
    token_id = uuidutils.generate_uuid(dashed=False)

    return token_id, o


class KeystoneClientFixture(testtools.TestCase):

    def setUp(self):
        super(KeystoneClientFixture, self).setUp()
        self.responses = self.useFixture(fixture.Fixture())
        self.barbican = barbicanclient.barbican.Barbican()

        self.test_arguments = {}

    def get_arguments(self, auth_version='v3'):
        if auth_version.lower() == 'v3':
            version_specific = {
                '--os-auth-url': V3_URL,
                '--os-project-name': 'my_project_name'
            }
        else:
            version_specific = {
                '--os-auth-url': V2_URL,
                '--os-identity-api-version': '2.0',
                '--os-tenant-name': 'my_tenant_name'
            }

        self.test_arguments.update(version_specific)
        return self._to_argv(self.test_arguments)

    def _to_argv(self, argument_dict):
        # Convert to argv to pass into the client
        argv = []
        for k, v in argument_dict.items():
            argv.extend([k, v])
        return argv

    def _delete_secret(self, auth_version):
        ref = '{0}/secrets/{1}'.format(BARBICAN_ENDPOINT,
                                       uuidutils.generate_uuid())

        # Mock delete secret
        self.responses.delete(ref, status_code=204)

        argv = self.get_arguments(auth_version)
        argv.extend(['--endpoint', BARBICAN_ENDPOINT, 'secret', 'delete', ref])

        try:
            self.barbican.run(argv=argv)
        except Exception:
            self.fail('failed to delete secret')

    def test_v2_auth(self):
        # Mock Keystone version discovery and token request
        self.responses.get(V2_URL, body=V2_VERSION_ENTRY)
        self.responses.post(
            '{0}/tokens'.format(V2_URL),
            json=generate_v2_project_scoped_token()
        )

        self._delete_secret('v2')

    def test_v3_auth(self):
        # Mock Keystone version discovery and token request
        self.responses.get(V3_URL, text=V3_VERSION_ENTRY)
        id, v3_token = generate_v3_project_scoped_token()

        self.responses.post(
            '{0}/auth/tokens'.format(V3_URL),
            json=v3_token,
            headers={'X-Subject-Token': '1234'}
        )

        self._delete_secret('v3')
