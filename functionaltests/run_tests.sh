#!/bin/bash
#
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
# Where tempest code lives

TEMPEST_DIR=${TEMPEST_DIR:-/opt/stack/new/tempest}

# Install tempest
pip install -e $TEMPEST_DIR

# Install test-requirements
pip install -r /opt/stack/new/python-barbicanclient/test-requirements.txt

echo "Running functional tests on $(python -V)"

nosetests -v .
