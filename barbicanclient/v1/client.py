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

from barbicanclient import client as base_client
from barbicanclient.v1 import acls
from barbicanclient.v1 import cas
from barbicanclient.v1 import containers
from barbicanclient.v1 import orders
from barbicanclient.v1 import secrets

LOG = logging.getLogger(__name__)


class Client(object):

    def __init__(self, session=None, *args, **kwargs):
        """Barbican client object used to interact with barbican service.

        :param session: An instance of keystoneauth1.session.Session that
            can be either authenticated, or not authenticated.  When using
            a non-authenticated Session, you must provide some additional
            parameters.  When no session is provided it will default to a
            non-authenticated Session.
        :param endpoint: Barbican endpoint url. Required when a session is not
            given, or when using a non-authenticated session.
            When using an authenticated session, the client will attempt
            to get an endpoint from the session.
        :param project_id: The project ID used for context in Barbican.
            Required when a session is not given, or when using a
            non-authenticated session.
            When using an authenticated session, the project ID will be
            provided by the authentication mechanism.
        :param verify: When a session is not given, the client will create
            a non-authenticated session.  This parameter is passed to the
            session that is created.  If set to False, it allows
            barbicanclient to perform "insecure" TLS (https) requests.
            The server's certificate will not be verified against any
            certificate authorities.
            WARNING: This option should be used with caution.
        :param service_type: Used as an endpoint filter when using an
            authenticated keystone session. Defaults to 'key-management'.
        :param service_name: Used as an endpoint filter when using an
            authenticated keystone session.
        :param interface: Used as an endpoint filter when using an
            authenticated keystone session. Defaults to 'public'.
        :param region_name: Used as an endpoint filter when using an
            authenticated keystone session.
        """
        self.client = base_client._HTTPClient(session=session, *args, **kwargs)

        self.secrets = secrets.SecretManager(self.client)
        self.orders = orders.OrderManager(self.client)
        self.containers = containers.ContainerManager(self.client)
        self.cas = cas.CAManager(self.client)
        self.acls = acls.ACLManager(self.client)
