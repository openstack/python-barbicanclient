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
