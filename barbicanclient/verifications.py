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
from barbicanclient import base
from barbicanclient.openstack.common.gettextutils import _
from barbicanclient.openstack.common import log as logging
from barbicanclient.openstack.common import timeutils


LOG = logging.getLogger(__name__)


class Verification(object):

    def __init__(self, verif_dict):
        """
        Builds a verification object from a dictionary.
        """
        self.verif_ref = verif_dict['verification_ref']
        self.resource_type = verif_dict['resource_type']
        self.resource_ref = verif_dict['resource_ref']
        self.resource_action = verif_dict['resource_action']
        self.impersonation_allowed = verif_dict['impersonation_allowed']
        self.is_verified = verif_dict.get('is_verified', False)

        self.error_status_code = verif_dict.get('error_status_code', None)
        self.error_reason = verif_dict.get('error_reason', None)
        self.status = verif_dict.get('status')
        self.created = timeutils.parse_isotime(verif_dict['created'])
        if verif_dict.get('updated') is not None:
            self.updated = timeutils.parse_isotime(verif_dict['updated'])
        else:
            self.updated = None

    def __str__(self):
        strg = ("Verification - verification href: {0}\n"
                "               resource_type: {1}\n"
                "               resource_ref: {2}\n"
                "               resource_action: {3}\n"
                "               impersonation_allowed: {4}\n"
                "               is_verified: {5}\n"
                "               created: {6}\n"
                "               status: {7}\n"
                ).format(self.verif_ref,
                         self.resource_type,
                         self.resource_ref,
                         self.resource_action,
                         self.impersonation_allowed,
                         self.is_verified,
                         self.created,
                         self.status)

        if self.error_status_code:
            strg = ''.join([strg, ("               error_status_code: {0}\n"
                                   "               error_reason: {1}\n"
                                   ).format(self.error_status_code,
                                            self.error_reason)])
        return strg

    def __repr__(self):
        return 'Verification(verification_ref={0})'.format(self.verif_ref)


class VerificationManager(base.BaseEntityManager):

    def __init__(self, api):
        super(VerificationManager, self).__init__(api, 'verifications')

    def create(self,
               resource_type=None,
               resource_ref=None,
               resource_action=None,
               impersonation_allowed=False):
        """
        Creates a new Verification in Barbican

        :param resource_type: Type of resource to verify
        :param resource_ref: Reference to resource
        :param resource_action: Action to be performed on or with the resource
        :param impersonation_allowed: True if users/projects interacting
        :                             with resource can be impersonated
        :returns: Verification href for the created verification
        """
        LOG.debug(_("Creating verification"))

        verif_dict = {'resource_type': resource_type,
                      'resource_ref': resource_ref,
                      'resource_action': resource_action,
                      'impersonation_allowed': impersonation_allowed}
        self._remove_empty_keys(verif_dict)

        LOG.debug(_("Request body: {0}").format(verif_dict))

        resp = self.api.post(self.entity, verif_dict)
        return resp['verification_ref']

    def get(self, verification_ref):
        """
        Returns a verification object

        :param verification_ref: The href for the verification instance
        """
        LOG.debug(_("Getting verification - "
                    "Verification href: {0}").format(verification_ref))
        if not verification_ref:
            raise ValueError('verif_ref is required.')
        resp = self.api.get(verification_ref)
        return Verification(resp)

    def delete(self, verification_ref):
        """
        Deletes a verification

        :param verification_ref: The href for the verification instance
        """
        if not verification_ref:
            raise ValueError('verif_ref is required.')
        self.api.delete(verification_ref)

    def list(self, limit=10, offset=0):
        """
        Lists all verifications for the tenant

        :param limit: Max number of verifications returned
        :param offset: Offset verifications to begin list
        :returns: list of Verification objects
        """
        LOG.debug('Listing verifications - '
                  'offset {0} limit {1}'.format(offset, limit))
        href = '{0}/{1}'.format(self.api.base_url, self.entity)
        params = {'limit': limit, 'offset': offset}
        resp = self.api.get(href, params)

        return [Verification(o) for o in resp['verifications']]
