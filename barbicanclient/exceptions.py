# Copyright (c) 2015 Rackspace, Inc.
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


class BarbicanException(Exception):
    pass


class PayloadException(BarbicanException):
    pass


class UnsupportedVersion(BarbicanException):
    """User is trying to use an unsupported version of the API."""
    pass


class HTTPError(Exception):

    """Base exception for HTTP errors."""

    def __init__(self, message, status_code=0):
        super(HTTPError, self).__init__(message)
        self.status_code = status_code


class HTTPServerError(HTTPError):

    """Raised for 5xx responses from the server."""
    pass


class HTTPClientError(HTTPError):

    """Raised for 4xx responses from the server."""
    pass


class HTTPAuthError(HTTPError):

    """Raised for 401 Unauthorized responses from the server."""
    def __init__(self, message, status_code=401):
        super(HTTPError, self).__init__(message, status_code)
