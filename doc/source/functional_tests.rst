Running Functional Tests
========================

In order to run functional tests you must enter into the top-level directory
of the python-barbicanclient and run:

.. code-block:: bash

    tox -e functional

By default, the functional tox job will use nosetests to execute the functional
tests. This is primarily due to nose being a very well known and common
workflow among developers.

Prerequisites
-------------

In order to run functional tests, Barbican must be running and configured to
use the Keystone Middleware. For more information on setting up this up
please visit http://docs.openstack.org/developer/barbican/setup/keystone.html


Functional Test Configuration
-----------------------------

A configuration file for functional tests must be edited before the tests
can be run. In the top-level directory of the python-barbicanclient, edit
``/etc/functional_tests.conf`` to the values you setup in Keystone.

.. code-block:: bash

    [DEFAULT]
    # Leaving this as a placeholder

    [keymanager]
    # Replace values that represent barbican server and user information
    url=http://localhost:9311
    username=barbican
    password=secretservice
    project_name=service
    project_id=service
    #max_payload_size=10000
    project_domain_name=Default

    [identity]
    # Replace these with values that represent your identity configuration
    uri=http://localhost:5000/v2.0
    uri_v3=http://localhost:5000/v3
    auth_version=v3

    username=admin
    tenant_name=admin
    password=password
    domain_name=Default

    admin_username=admin
    admin_tenant_name=admin
    admin_password=password
    admin_domain_name=Default


    [identity-feature-enabled]
    # Leaving this as a placeholder
