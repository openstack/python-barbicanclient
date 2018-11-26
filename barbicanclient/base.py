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
import logging
import uuid


LOG = logging.getLogger(__name__)


def filter_null_keys(dictionary):
    return dict(((k, v) for k, v in dictionary.items() if v is not None))


def censored_copy(data_dict, censor_keys):
    '''Returns redacted dict copy for censored keys'''
    if censor_keys is None:
        censor_keys = []
    return {k: v if k not in censor_keys else '<redacted>' for k, v in
            data_dict.items()}


def validate_ref_and_return_uuid(ref, entity):
    """Verifies that there is a real uuid (possibly at the end of a uri)

    :return: The uuid.UUID object
    :raises ValueError: If it cannot correctly parse the uuid in the ref.
    """
    try:
        # This works for a ref *or* a UUID, since we just pick the last piece
        ref_pieces = ref.rstrip('/').rsplit('/', 1)
        return uuid.UUID(ref_pieces[-1])
    except Exception:
        raise ValueError('{0} incorrectly specified.'.format(entity))


def calculate_uuid_ref(ref, entity):
    entity_uuid = validate_ref_and_return_uuid(
        ref, entity.capitalize().rstrip('s'))
    entity_ref = "{entity}/{uuid}".format(entity=entity, uuid=entity_uuid)
    LOG.info("Calculated %s uuid ref: %s", entity.capitalize(), entity_ref)
    return entity_ref


class ImmutableException(Exception):
    def __init__(self, attribute=None):
        message = "This object is immutable!"
        super(ImmutableException, self).__init__(message)


class BaseEntityManager(object):
    def __init__(self, api, entity):
        self._api = api
        self._entity = entity

    def total(self):
        """Returns the total number of entities stored in Barbican."""
        params = {'limit': 0, 'offset': 0}
        resp = self._api.get(self._entity, params=params)

        return resp['total']
