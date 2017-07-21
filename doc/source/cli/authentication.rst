Authentication
==============

Keystone Authentication
-----------------------

The client defers authentication to `Keystone Sessions`_, which provide several
authentication plugins in the `keystoneauth1.identity` namespace.  Below we give
examples of the most commonly used auth plugins.

.. _`Keystone Sessions`: https://docs.openstack.org/keystoneauth/latest/using-sessions.html

Keystone API Version 3 Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authentication using Keystone API Version 3 can be achieved using the
`keystoneauth1.identity.V3Password` auth plugin.

Example:

  .. code-block:: python

    from barbicanclient import client
    from keystoneauth1 import identity
    from keystoneauth1 import session

    auth = identity.V3Password(auth_url='http://localhost:5000/v3',
                               username='admin_user',
                               user_domain_name='Default',
                               password='password',
                               project_name='demo',
                               project_domain_name='Default')
    sess = session.Session(auth=auth)
    barbican = client.Client(session=sess)

Keystone API Version 2 Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authentication using Keystone API Version 2 can be achieved using the
`keystoneauth1.identity.V2Password` auth plugin.

Example:

  .. code-block:: python

    from barbicanclient import client
    from keystoneauth1 import identity
    from keystoneauth1 import session

    auth = identity.V2Password(auth_url='http://localhost:5000/v2.0',
                               username='admin_user',
                               password='password',
                               tenant_name='demo')
    sess = session.Session(auth=auth)
    barbican = client.Client(session=sess)

Unauthenticated Context
-----------------------

Sometimes it may be useful to work with the client in an unauthenticated
context, for example when using a development instance of Barbican that is
not yet configured to use Keystone for authentication.  In this case, the
Barbican Service endpoint must be provided, in addition to the Project ID that
will be used for context (i.e. the project that owns the secrets you'll be
working with).

Example:

  .. code-block:: python

    from barbicanclient import client

    barbican = client.Client(endpoint='http://localhost:9311',
                             project_id='123456')


CLI Authentication
==================

Keystone V3 Authentication
--------------------------

Barbican can be configured to use Keystone for authentication. The user's
credentials can be passed to Barbican via arguments.

.. code-block:: bash

    $ barbican --os-auth-url <keystone-v3-url> --os-project-domain-id \
    <domain id> --os-user-domain-id <user domain id> --os-username <username> \
    --os-password <password> --os-project-name <project-name> secret list

This can become annoying and tedious, so authentication via Keystone can
also be configured by setting environment variables. Barbican uses the same env
variables as python-keystoneclient so if you already have keystone client
configured you can skip this section.

An example clientrc file is provided in the main python-barbicanclient
directory.

.. code-block:: bash

    export OS_PROJECT_NAME=<YourProjectName>

    # Either Project Domain ID or Project Domain Name is required
    export OS_PROJECT_DOMAIN_ID=<YourProjectDomainID>
    export OS_PROJECT_DOMAIN_NAME=<YourProjectDomainName>

    # Either User Domain ID or User Domain Name is required
    export OS_USER_DOMAIN_ID=<YourUserDomainID>
    export OS_USER_DOMAIN_NAME=<YourUserDomainName>

    # Either User ID or Username can be used
    export OS_USER_ID =<YourUserID>
    export OS_USERNAME=<YourUserName>

    export OS_PASSWORD=<YourPassword>

    # OS_AUTH_URL should be your location of Keystone
    # Barbican Client defaults to Keystone V3
    export OS_AUTH_URL="<YourAuthURL>:5000/v3/"
    export BARBICAN_ENDPOINT="<YourBarbicanEndpoint>:9311"


Make any appropriate changes to this file.

You will need to source it into your environment on each load:

.. code-block:: bash

    source ~/clientrc

If you would like, you can configure your bash to load the variables on
each login:

.. code-block:: bash

    echo "source ~/clientrc" >> ~/.bashrc

Keystone Token Authentication
-----------------------------

Barbican can be configured to use Keystone tokens for authentication. The
user's credentials can be passed to Barbican via arguments.

.. code-block:: bash

    $ barbican --os-auth-url <auth_endpoint> --os-auth-token <auth_token> \
    --os-project-id <project_id> secret list

Much like normal password authentication you can specify these values via
environmental variables. Refer to `Keystone V3 authentication`_ for more
information.


No Auth Mode
------------

When working with a Barbican instance that does not use Keystone authentication
(e.g. during development) you can use the :code:`--no-auth` option. If you do
this, you'll have to specify the Barbican endpoint and project ID
:code:`--os-project-id`. This is because Barbican normally gets the endpoint
and tenant ID from Keystone.

