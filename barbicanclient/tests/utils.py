"""
Copyright 2022 Red Hat Inc.

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

from unittest import mock

from keystoneauth1 import identity
from keystoneauth1 import session


_DEFAULT_ENDPOINT = "http://192.168.1.23/key-manager/"

STABLE_RESPONSE = {
    'version': {
        'id': 'v1',
        'status': 'stable',
        'links': [
            {
                'rel': 'self',
                'href': 'http://192.168.1.23/key-manager/v1/'
            }, {
                'rel': 'describedby',
                'type': 'text/html',
                'href': 'https://docs.openstack.org/'
            }],
        'media-types': [{
            'base': 'application/json',
            'type': 'application/vnd.openstack.key-manager-v1+json'
        }]
    }
}


def get_custom_current_response(min_version="1.0", max_version="1.1"):
    return {
        'version': {
            'id': 'v1',
            'status': 'CURRENT',
            'min_version': min_version,
            'max_version': max_version,
            'links': [
                {
                    'rel': 'self',
                    'href': 'http://192.168.1.23/key-manager/v1/'
                }, {
                    'rel': 'describedby',
                    'type': 'text/html',
                    'href': 'https://docs.openstack.org/'
                }
            ]
        }
    }


def mock_microversion_response(response=STABLE_RESPONSE):
    response_mock = mock.MagicMock()
    response_mock.json.return_value = response
    return response_mock


def get_version_endpoint(endpoint=None):
    return "{}/v1/".format(endpoint or _DEFAULT_ENDPOINT)


def mock_session():
    auth = identity.Password(
        auth_url="http://localhost/identity/v3",
        username="username",
        password="password",
        project_name="project_name",
        default_domain_id='default')
    sess = session.Session(auth=auth)
    return sess


def mock_session_get_endpoint(sess, endpoint_response):
    sess.get_endpoint = mock.MagicMock()
    sess.get_endpoint.return_value = endpoint_response


def mock_session_get(sess, get_response):
    response_mock = mock.MagicMock()
    response_mock.json.return_value = get_response

    sess.get = mock.MagicMock()
    sess.get.return_value = response_mock


def mock_session_with_get_and_get_endpoint(endpoint_response, get_response):
    sess = mock_session()
    mock_session_get(get_response)
    mock_session_get_endpoint(endpoint_response)

    return sess


def get_server_supported_versions(min_version, max_version):
    if min_version and max_version:
        return get_custom_current_response(min_version, max_version)
    return STABLE_RESPONSE


def mock_get_secret_for_client(client, consumers=[]):
    api_get_return = {
        'created': '2022-11-25T15:17:56',
        'updated': '2022-11-25T15:17:56',
        'status': 'ACTIVE',
        'name': 'Dummy secret',
        'secret_type': 'opaque',
        'expiration': None,
        'algorithm': None,
        'bit_length': None,
        'mode': None,
        'creator_id': '8ddfdbc4d92440369569af0589a20fa4',
        'consumers': consumers or [],
        'content_types': {'default': 'text/plain'},
        'secret_ref': 'http://192.168.1.23/key-manager/v1/'
                      'secrets/d46cfe10-c8ba-452f-a82f-a06834e45604'
    }
    client.client.get = mock.MagicMock()
    client.client.get.return_value = api_get_return


def mock_delete_secret_for_responses(responses, entity_href):
    responses.delete(entity_href, status_code=204)
