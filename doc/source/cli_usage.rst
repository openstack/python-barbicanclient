Usage
=====

.. code-block:: bash

    usage: barbican [--version] [-v] [--log-file LOG_FILE] [-q] [-h] [--debug]
                    [--no-auth] [--os-identity-api-version <identity-api-version>]
                    [--os-auth-url <auth-url>] [--os-username <auth-user-name>]
                    [--os-user-id <auth-user-id>] [--os-password <auth-password>]
                    [--os-user-domain-id <auth-user-domain-id>]
                    [--os-user-domain-name <auth-user-domain-name>]
                    [--os-tenant-name <auth-tenant-name>]
                    [--os-tenant-id <tenant-id>]
                    [--os-project-id <auth-project-id>]
                    [--os-project-name <auth-project-name>]
                    [--os-project-domain-id <auth-project-domain-id>]
                    [--os-project-domain-name <auth-project-domain-name>]
                    [--endpoint <barbican-url>] [--insecure]
                    [--os-cacert <ca-certificate>] [--os-cert <certificate>]
                    [--os-key <key>] [--timeout <seconds>]


The examples below assume that credentials have been saved to your environment.
If you don't have variables saved to your environment or you wish to use
different credentials than those defined, any of the optional arguments listed
above may be passed to Barbican.

Barbican takes a positional argument <entity>, which specifies whether you
wish to operate on a secret or an order.

Secrets
-------

.. code-block:: bash

    $ barbican secret <action>

A subcommand describing the action to be performed should follow.
The subcommands are mostly the same for secrets and orders, although some
optional arguments only apply to one or the other.

Subcommand actions that a user can take for secrets are:

.. code-block:: bash

    secret delete  Delete a secret by providing its URI.
    secret get     Retrieve a secret by providing its URI.
    secret list    List secrets.
    secret store   Store a secret in Barbican.

Each subcommand takes in a different set of arguments, and the help message
varies from one to another. The help message for **get** can be seen below.

.. code-block:: bash

    $  barbican help secret get
    usage: barbican secret get [-h] [-f {shell,table,value}] [-c COLUMN]
                               [--max-width <integer>] [--prefix PREFIX]
                               [--decrypt] [--payload]
                               [--payload_content_type PAYLOAD_CONTENT_TYPE]
                               URI

    Retrieve a secret by providing its URI.

    positional arguments:
      URI                   The URI reference for the secret.

    optional arguments:
      -h, --help            show this help message and exit
      --decrypt, -d         if specified, retrieve the unencrypted secret data;
                            the data type can be specified with --payload-content-
                            type.
      --payload, -p         if specified, retrieve the unencrypted secret data;
                            the data type can be specified with --payload-content-
                            type. If the user wishes to only retrieve the value of
                            the payload they must add "-f value" to format
                            returning only the value of the payload
      --payload_content_type PAYLOAD_CONTENT_TYPE, -t PAYLOAD_CONTENT_TYPE
                            the content type of the decrypted secret (default:
                            text/plain.

    output formatters:
      output formatter options

      -f {shell,table,value}, --format {shell,table,value}
                            the output format, defaults to table
      -c COLUMN, --column COLUMN
                            specify the column(s) to include, can be repeated

    table formatter:
      --max-width <integer>
                            Maximum display width, 0 to disable

    shell formatter:
      a format a UNIX shell can parse (variable="value")

      --prefix PREFIX       add a prefix to all variable names


Secret Create
~~~~~~~~~~~~~

.. code-block:: bash

    $ barbican secret store -n mysecretname -p 'my secret value'

    +---------------+-----------------------------------------------------------------------+
    | Field         | Value                                                                 |
    +---------------+-----------------------------------------------------------------------+
    | Secret href   | http://localhost:9311/v1/secrets/a70a45d8-4076-42a2-b111-8893d3b92a3e |
    | Name          | mysecretname                                                          |
    | Created       | None                                                                  |
    | Status        | None                                                                  |
    | Content types | None                                                                  |
    | Algorithm     | aes                                                                   |
    | Bit length    | 256                                                                   |
    | Mode          | cbc                                                                   |
    | Expiration    | None                                                                  |
    +---------------+-----------------------------------------------------------------------+

Secret Get
~~~~~~~~~~

.. code-block:: bash

    $ barbican secret get http://localhost:9311/v1/secrets/a70a45d8-4076-42a2-b111-8893d3b92a3e

    +---------------+-----------------------------------------------------------------------+
    | Field         | Value                                                                 |
    +---------------+-----------------------------------------------------------------------+
    | Secret href   | http://localhost:9311/v1/secrets/a70a45d8-4076-42a2-b111-8893d3b92a3e |
    | Name          | mysecretname                                                          |
    | Created       | 2015-04-16 20:36:40.334696+00:00                                      |
    | Status        | ACTIVE                                                                |
    | Content types | {u'default': u'application/octet-stream'}                             |
    | Algorithm     | aes                                                                   |
    | Bit length    | 256                                                                   |
    | Mode          | cbc                                                                   |
    | Expiration    | None                                                                  |
    +---------------+-----------------------------------------------------------------------+

To retrieve only the raw value of the payload we have introduced the :code:`-p`
or :code:`--payload` option paired with the :code:`-f value` cliff formatting
option. (The :code:`--decrypt` option will perform the same action; however,
it will be deprecated)

.. code-block:: bash

    $ barbican secret get http://localhost:9311/v1/secrets/a70a45d8-4076-42a2-b111-8893d3b92a3e --payload -f value
    my secret value

Secret Delete
~~~~~~~~~~~~~

.. code-block:: bash

    $ barbican secret delete http://localhost:9311/v1/secrets/a70a45d8-4076-42a2-b111-8893d3b92a3e


Secret List
~~~~~~~~~~~

.. code-block:: bash

    $ barbican secret list

    +-----------------------------------------------------------------------+------+----------------------------------+--------+-------------------------------------------+-----------+------------+------+------------+
    | Secret href                                                           | Name | Created                          | Status | Content types                             | Algorithm | Bit length | Mode | Expiration |
    +-----------------------------------------------------------------------+------+----------------------------------+--------+-------------------------------------------+-----------+------------+------+------------+
    | http://localhost:9311/v1/secrets/bb3d8c20-8ea5-4bfc-9645-c8da79c8b371 | None | 2015-04-15 20:37:37.501475+00:00 | ACTIVE | {u'default': u'application/octet-stream'} | aes       |        256 | cbc  | None       |
    +-----------------------------------------------------------------------+------+----------------------------------+--------+-------------------------------------------+-----------+------------+------+------------+