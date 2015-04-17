Authentication
==============

Keystone Authentication
-----------------------

The client defers authentication to `Keystone Sessions`_, which provide several
authentication plugins in the `keystoneclient.auth` namespace.  Below we give
examples of the most commonly used auth plugins.

.. _`Keystone Sessions`: http://docs.openstack.org/developer/python-keystoneclient/using-sessions.html

Keystone API Version 3 Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authentication using Keystone API Version 3 can be achieved using the
`keystoneclient.auth.identity.v3.Password` auth plugin.

Example::

    from keystoneclient.auth import identity
    from keystoneclient import session
    from barbicanclient import client

    auth = identity.v3.Password(auth_url='http://localhost:5000/v3',
                                username='admin_user',
                                user_domain_name='Default',
                                password='password',
                                project_name='demo'
                                project_domain_name='Default')
    sess = session.Session(auth=auth)
    barbican = client.Client(session=sess)

Keystone API Version 2 Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authentication using Keystone API Version 2 can be achieved using the
`keystoneclient.auth.identity.v2.Password` auth plugin.

Example::

    from keystoneclient.auth import identity
    from keystoneclient import session
    from barbicanclient import client

    auth = identity.v2.Password(auth_url='http://localhost:5000/v2.0',
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

Example::

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
    --os-password <password> --os-project-name <project-name> --endpoint \
    <barbican-endpoint> secret list

This can become annoying and tedious, so authentication via Keystone can
also be configured by setting environment variables. Barbican uses the same env
variables as python-keystoneclient so if you already have keystone client
configured you can skip this section.

An example clientrc file is provided in the main python-barbicanclient
directory.

.. code-block:: bash

    export OS_PROJECT_NAME=admin

    # Either Project ID or Project Name is required
    export OS_PROJECT_DOMAIN_ID=<YourProjectID>
    export OS_PROJECT_DOMAIN_NAME=<YourProjectName>

    # Either User ID or User Name is required
    export OS_USER_DOMAIN_ID=<YourUserDomainID>
    export OS_USER_DOMAIN_NAME=<YourUserDomainName>
    export OS_USERNAME=admin
    export OS_PASSWORD=password

    # OS_AUTH_URL should be your location of Keystone
    # Barbican Client defaults to Keystone V3
    export OS_AUTH_URL="http://localhost:5000/v3/"
    export BARBICAN_ENDPOINT="http://localhost:9311"


Make any appropriate changes to this file.

You will need to source it into your environment on each load:

.. code-block:: bash

    source ~/clientrc

If you would like, you can configure your bash to load the variables on
each login:

.. code-block:: bash

    echo "source ~/clientrc" >> ~/.bashrc


No Auth Mode
------------

When working with a Barbican instance that does not use Keystone authentication
(e.g. during development) you can use the :code:`--no-auth` option. If you do
this, you'll have to specify the Barbican endpoint and project ID
:code:`--os-project-id`. This is because Barbican normally gets the endpoint
and tenant ID from Keystone.

