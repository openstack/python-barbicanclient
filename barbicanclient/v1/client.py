# Copyright (c) 2016 GohighSec, Inc.
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

import logging

from keystoneauth1 import discover

from barbicanclient import client as base_client
from barbicanclient.v1 import acls
from barbicanclient.v1 import cas
from barbicanclient.v1 import containers
from barbicanclient.v1 import orders
from barbicanclient.v1 import secrets


LOG = logging.getLogger(__name__)
_SUPPORTED_MICROVERSIONS = [(1, 0),
                            (1, 1)]
# For microversion 1.0, API status is "stable"
_STABLE = "STABLE"


class Client(object):

    def __init__(self, session=None, *args, **kwargs):
        """Barbican client implementation for API version v1

        This class is dynamically loaded by the factory function
        `barbicanclient.client.Client`.  It's recommended to use that
        function instead of making instances of this class directly.
        """
        microversion = kwargs.pop('microversion', None)
        if microversion:
            if not self._validate_microversion(
                session,
                kwargs.get('endpoint'),
                kwargs.get('version'),
                kwargs.get('service_type'),
                kwargs.get('service_name'),
                kwargs.get('interface'),
                kwargs.get('region_name'),
                microversion
            ):
                raise ValueError(
                    "Endpoint does not support microversion {}".format(
                        microversion))
            kwargs['default_microversion'] = microversion

        # TODO(dmendiza): This should be a private member
        self.client = base_client._HTTPClient(session=session, *args, **kwargs)

        self.secrets = secrets.SecretManager(self.client)
        self.orders = orders.OrderManager(self.client)
        self.containers = containers.ContainerManager(self.client)
        self.cas = cas.CAManager(self.client)
        self.acls = acls.ACLManager(self.client)

    def _validate_microversion(self, session, endpoint, version, service_type,
                               service_name, interface, region_name,
                               microversion):
        # first we make sure that the microversion is something we understand
        normalized = discover.normalize_version_number(microversion)
        if normalized not in _SUPPORTED_MICROVERSIONS:
            raise ValueError("Invalid microversion {}".format(microversion))
        microversion = discover.version_to_string(normalized)

        if not endpoint:
            endpoint = session.get_endpoint(
                service_type=service_type,
                service_name=service_name,
                interface=interface,
                region_name=region_name,
                version=version
            )

        resp = discover.get_version_data(
            session, endpoint,
            version_header='key-manager ' + microversion)
        if resp:
            resp = resp[0]
            status = resp['status'].upper()

            if status == _STABLE:
                # status is only set to STABLE in two cases
                # 1. when the server is older and is ignoring the microversion
                #    header
                # 2. when we ask for microversion 1.0 and the server
                #    undertsands the header
                # in either case min/max will be 1.0
                min_ver = '1.0'
                max_ver = '1.0'
            else:
                # any other status will have a min/max
                min_ver = resp['version']['min_version']
                max_ver = resp['version']['max_version']
            return discover.version_between(min_ver, max_ver, microversion)

        # TODO(afariasa) What should be returned? error?
        return False
