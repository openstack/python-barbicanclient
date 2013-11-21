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
Base utilites to build API operation managers.
"""


class BaseEntityManager(object):
    def __init__(self, api, entity):
        self.api = api
        self.entity = entity

    def _remove_empty_keys(self, dictionary):
        for k in dictionary.keys():
            if dictionary[k] is None:
                dictionary.pop(k)

    def total(self):
        """
        Returns the total number of entities stored in Barbican.
        """
        href = '{0}/{1}'.format(self.api.base_url, self.entity)
        params = {'limit': 0, 'offset': 0}
        resp = self.api.get(href, params)

        return resp['total']
