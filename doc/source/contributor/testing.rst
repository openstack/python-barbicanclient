Writing and Running Barbican Client Tests
=========================================

As a part of every code review that is submitted to the python-barbicanclient
project there are a number of gating jobs which aid in the prevention of
regression issues within python-barbicanclient. As a result, a
python-barbicanclient developer should be familiar with running
python-barbicanclient tests locally.

For your convenience we provide the ability to run all tests through
the ``tox`` utility. If you are unfamiliar with tox please see
refer to the `tox documentation`_ for assistance.

.. _`tox documentation`: https://tox.readthedocs.org/en/latest/

Unit Tests
----------

We follow the `Tested Runtimes <https://governance.openstack.org/tc/reference/project-testing-interface.html#tested-runtimes>`
as defined by the Technical Committe every cycle.

All available test environments within the tox configuration will execute
when calling ``tox``. If you want to run them independently, you can do so
with the following command:

.. code-block:: bash

    # Executes tests on Python 3.9
    tox -e py39

.. note::

    If you do not have the appropriate Python versions available, consider
    setting up PyEnv to install multiple versions of Python. See the
    documentation `setting up a Barbican development environment <https://github.com/openstack/barbican/blob/master/doc/source/contributor/dev.rst>`_.

.. note::

    Individual unit tests can also be run, using the following commands:

    .. code-block:: bash

        # runs a single test with the function named
        # test_should_entity_str
        tox -e py39 -- test_should_entity_str

        # runs only tests in the WhenTestingSecrets class and
        # the WhenTestingOrderManager class
        tox -e p39 -- '(WhenTestingSecrets|WhenTestingOrderManager)'

    The function name or class specified must be one located in the
    `barbicanclient/tests` directory.

    Groups of tests can also be run with a regex match after the ``--``.
    For more information on what can be done with ``stestr``, please see:
    https://stestr.readthedocs.io/en/latest/

You can also setup breakpoints in the unit tests. This can be done by
adding ``import pdb; pdb.set_trace()`` to the line of the unit test you
want to examine, then running the following command:

.. code-block:: bash

    tox -e debug

.. note::

    For a list of pdb commands, please see:
    https://docs.python.org/2/library/pdb.html

Functional Tests
----------------

Unlike running unit tests, the functional tests require Barbican and
Keystone services to be running in order to execute. For more
information on `setting up a Barbican development environment <https://github.com/openstack/barbican/blob/master/doc/source/contributor/dev.rst>`_
and using `Keystone with Barbican <https://github.com/openstack/barbican/blob/master/doc/source/configuration/keystone.rst>`_,
see our accompanying project documentation.

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


Once you have the appropriate services running and configured you can execute
the functional tests through tox.

.. code-block:: bash

    # Execute Barbican Functional Tests
    tox -e functional

.. note::

    In order to run individual functional test functions, you must use the
    following commands:

    .. code-block:: bash

        # runs only tests in the test_secrets.py file
        tox -e functional -- client/v1/functional/test_secrets.py

        # runs only tests in the SecretsTestCase class
        tox -e functional -- client/v1/functional/test_secrets.py:\
        SecretsTestCase

        # runs a single test with the function named
        # test_secret_create_defaults_check_content_types
        tox -e functional -- client/v1/functional/test_secrets.py:\
        SecretsTestCase.test_secret_create_defaults_check_content_types

    The path specified must be one located in the `functionaltests`
    directory.

Remote Debugging
----------------

In order to be able to hit break-points on API calls, you must use remote
debugging. This can be done by adding ``import rpdb; rpdb.set_trace()`` to
the line of the API call you wish to test. For example, adding the breakpoint
in ``def create`` in ``barbicanclient.secrets.py`` will allow you to hit the
breakpoint whenever the ``create`` function is called.

.. note::

    After performing the ``POST`` the application will freeze. In order to use
    ``rpdb``, you must open up another terminal and run the following:

    .. code-block:: bash

        # enter rpdb using telnet
        telnet localhost 4444

    Once in rpdb, you can use the same commands as pdb, as seen here:
    https://docs.python.org/2/library/pdb.html
