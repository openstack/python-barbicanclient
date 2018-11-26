# Copyright (c) 2015 Red Hat Inc.
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
import functools
import logging

from oslo_utils.timeutils import parse_isotime

from barbicanclient import base
from barbicanclient import formatter


LOG = logging.getLogger(__name__)


def lazy(func):
    @functools.wraps(func)
    def wrapper(self, *args):
        self._fill_lazy_properties()
        return func(self, *args)
    return wrapper


class CAFormatter(formatter.EntityFormatter):

    columns = ("CA href",
               "Name",
               "Description",
               "Created",
               "Updated",
               "Status",
               "Plugin Name",
               "Plugin CA ID",
               "Expiration"
               )

    def _get_formatted_data(self):
        created = self.created.isoformat() if self.created else None
        updated = self.updated.isoformat() if self.updated else None
        expiration = self.expiration.isoformat() if self.expiration else None
        data = (self.ca_ref,
                self.name,
                self.description,
                created,
                updated,
                self.status,
                self.plugin_name,
                self.plugin_ca_id,
                expiration
                )
        return data


class CA(CAFormatter):
    """Certificate authority

    CAs represent certificate authorities or subCAs with which the Barbican
    service is configured to interact.
    """
    _entity = 'cas'

    def __init__(self, api, meta=None, expiration=None,
                 plugin_name=None, plugin_ca_id=None,
                 ca_ref=None, created=None, updated=None,
                 status=None, creator_id=None):
        """Certificate authority

        CA objects should not be instantiated directly.  You should use
        the `create` or `get` methods of the
        :class:`barbicanclient.cas.CAManager` instead.
        """
        self._api = api
        self._ca_ref = ca_ref
        self._fill_from_data(
            meta=meta,
            expiration=expiration,
            plugin_name=plugin_name,
            plugin_ca_id=plugin_ca_id,
            created=created,
            updated=updated,
            status=status,
            creator_id=creator_id
        )

    @property
    def ca_ref(self):
        return self._ca_ref

    @property
    @lazy
    def name(self):
        return self._name

    @property
    @lazy
    def expiration(self):
        return self._expiration

    @property
    @lazy
    def description(self):
        return self._description

    @property
    @lazy
    def plugin_name(self):
        return self._plugin_name

    @property
    @lazy
    def plugin_ca_id(self):
        return self._plugin_ca_id

    @property
    @lazy
    def created(self):
        return self._created

    @property
    @lazy
    def updated(self):
        return self._updated

    @property
    @lazy
    def status(self):
        return self._status

    def _fill_from_data(self, meta=None, expiration=None,
                        plugin_name=None, plugin_ca_id=None, created=None,
                        updated=None, status=None, creator_id=None):
        self._name = None
        self._description = None
        if meta:
            for s in meta:
                key = list(s.keys())[0]
                value = list(s.values())[0]
                if key == 'name':
                    self._name = value
                if key == 'description':
                    self._description = value
        self._plugin_name = plugin_name
        self._plugin_ca_id = plugin_ca_id
        self._expiration = expiration
        self._creator_id = creator_id
        if self._expiration:
            self._expiration = parse_isotime(self._expiration)
        if self._ca_ref:
            self._status = status
            self._created = created
            self._updated = updated
            if self._created:
                self._created = parse_isotime(self._created)
            if self._updated:
                self._updated = parse_isotime(self._updated)
        else:
            self._status = None
            self._created = None
            self._updated = None

    def _fill_lazy_properties(self):
        if self._ca_ref and not self._plugin_name:
            uuid_ref = base.calculate_uuid_ref(self._ca_ref, self._entity)
            result = self._api.get(uuid_ref)
            self._fill_from_data(
                meta=result.get('meta'),
                expiration=result.get('expiration'),
                plugin_name=result.get('plugin_name'),
                plugin_ca_id=result.get('plugin_ca_id'),
                created=result.get('created'),
                updated=result.get('updated'),
                status=result.get('status')
            )

    def __repr__(self):
        if self._ca_ref:
            return 'CA(ca_ref="{0}")'.format(self._ca_ref)
        return 'CA(name="{0}")'.format(self._name)


class CAManager(base.BaseEntityManager):
    """Entity Manager for Secret entities"""

    def __init__(self, api):
        super(CAManager, self).__init__(api, 'cas')

    def get(self, ca_ref):
        """Retrieve an existing CA from Barbican

        :param str ca_ref: Full HATEOAS reference to a CA
        :returns: CA object retrieved from Barbican
        :rtype: :class:`barbicanclient.v1.cas.CA`
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug("Getting ca - CA href: {0}".format(ca_ref))
        base.validate_ref_and_return_uuid(ca_ref, 'CA')
        return CA(
            api=self._api,
            ca_ref=ca_ref
        )

    def list(self, limit=10, offset=0, name=None):
        """List CAs for the project

        This method uses the limit and offset parameters for paging,
        and also supports filtering.

        :param limit: Max number of CAs returned
        :param offset: Offset secrets to begin list
        :param name: Name filter for the list
        :returns: list of CA objects that satisfy the provided filter
            criteria.
        :rtype: list
        :raises barbicanclient.exceptions.HTTPAuthError: 401 Responses
        :raises barbicanclient.exceptions.HTTPClientError: 4xx Responses
        :raises barbicanclient.exceptions.HTTPServerError: 5xx Responses
        """
        LOG.debug('Listing CAs - offset {0} limit {1}'.format(offset, limit))
        params = {'limit': limit, 'offset': offset}
        if name:
            params['name'] = name

        response = self._api.get(self._entity, params=params)

        return [
            CA(api=self._api, ca_ref=s)
            for s in response.get('cas', [])
        ]
