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
Base utilities to build API operation managers.
"""
import uuid

import six


def filter_null_keys(dictionary):
    return dict(((k, v) for k, v in dictionary.items() if v is not None))


def validate_ref(ref, entity):
    try:
        # Split out the UUID from the ref URL
        url = six.moves.urllib.parse.urlparse(ref)
        parts = url.path.rstrip('/').split('/')
        # Attempt to load the UUID with uuid, which will raise if invalid
        uuid.UUID(parts[-1])
    except:
        raise ValueError('{0} incorrectly specified.'.format(entity))


class ImmutableException(Exception):
    def __init__(self, attribute=None):
        message = "This object is immutable!"
        super(ImmutableException, self).__init__(message)


class BaseEntityManager(object):
    def __init__(self, api, entity):
        self._api = api
        self._entity = entity

    def total(self):
        """
        Returns the total number of entities stored in Barbican.
        """
        href = '{0}/{1}'.format(self._api._base_url, self._entity)
        params = {'limit': 0, 'offset': 0}
        resp = self._api._get(href, params)

        return resp['total']
