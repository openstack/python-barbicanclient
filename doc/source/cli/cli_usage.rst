CLI Usage
=========

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
                    [--os-auth-token <auth-token>]
                    [--endpoint <barbican-url>] [--insecure]
                    [--os-cacert <ca-certificate>] [--os-cert <certificate>]
                    [--os-key <key>] [--timeout <seconds>]


The examples below assume that credentials have been saved to your environment.
If you don't have variables saved to your environment or you wish to use
different credentials than those defined, any of the optional arguments listed
above may be passed to Barbican.

Barbican takes a positional argument <entity>, which specifies whether you wish
to operate on a secret or an order.

Secrets
-------

.. code-block:: bash

    $ barbican secret <action>

A subcommand describing the action to be performed should follow. The
subcommands are mostly the same for secrets and orders, although some optional
arguments only apply to one or the other.

Subcommand actions that a user can take for secrets are:

.. code-block:: bash

    secret consumer Allow operations with secret consumers.
    secret delete   Delete a secret by providing its URI.
    secret get      Retrieve a secret by providing its URI.
    secret list     List secrets.
    secret store    Store a secret in Barbican.

Each subcommand takes in a different set of arguments, and the help message
varies from one to another. The help message for **get** can be seen below.

.. code-block:: bash

    $  barbican help secret get
    usage: barbican secret get [-h] [-f {json,shell,table,value,yaml}] [-c COLUMN]
                               [--max-width <integer>] [--fit-width]
                               [--print-empty] [--noindent] [--prefix PREFIX]
                               [--decrypt | --payload | --file <filename>]
                               [--payload_content_type PAYLOAD_CONTENT_TYPE]
                               URI

    Retrieve a secret by providing its URI.

    positional arguments:
      URI                   The URI reference for the secret.

    optional arguments:
      -h, --help            show this help message and exit
      --decrypt, -d         if specified, retrieve the unencrypted secret data.
      --payload, -p         if specified, retrieve the unencrypted secret data.
      --file <filename>, -F <filename>
                            if specified, save the payload to a new file with the
                            given filename.
      --payload_content_type PAYLOAD_CONTENT_TYPE, -t PAYLOAD_CONTENT_TYPE
                            the content type of the decrypted secret (default:
                            text/plain).

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

Instead of using the :code:`-p` or :code:`--payload` option with the
value of the secret in the command line, the value of
the secret may be stored in a file.  For this method the
:code:`-F <filename>` or :code:`--file <filename>` option can be used.

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
    | Content types | {'default': 'application/octet-stream'}                               |
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

Instead of using the :code:`-p` or :code:`--payload` option with the
value of the secret returned to stdout, the value of
the secret may be written to a file.  For this method the
:code:`-F <filename>` or :code:`--file <filename>` option can be used.

Secret Delete
~~~~~~~~~~~~~

If a secret to be deleted has at least one consumer, the secret can only be deleted after removing all consumers,
or by using the `--force` parameter

.. code-block:: bash

    $ barbican secret delete http://localhost:9311/v1/secrets/a70a45d8-4076-42a2-b111-8893d3b92a3e

.. code-block:: bash

    $ barbican secret delete http://localhost:9311/v1/secrets/0207414d-c23b-47f6-9cef-f44e907ac7a8
    Secret has consumers! Remove them first or use the force parameter to delete it.

.. code-block:: bash

    $ barbican secret delete --force http://localhost:9311/v1/secrets/0207414d-c23b-47f6-9cef-f44e907ac7a8

Secret Update
~~~~~~~~~~~~~

.. code-block:: bash

    $ barbican secret update http://localhost:9311/v1/secrets/a70a45d8-4076-42a2-b111-8893d3b92a3e ``my_payload``

In order for a secret to be updated it must have been created without a payload.
``my_payload`` will be added as the secret's payload.

Secret List
~~~~~~~~~~~

.. code-block:: bash

    $ barbican secret list

    +-----------------------------------------------------------------------+------+----------------------------------+--------+-----------------------------------------+-----------+------------+------+------------+
    | Secret href                                                           | Name | Created                          | Status | Content types                           | Algorithm | Bit length | Mode | Expiration |
    +-----------------------------------------------------------------------+------+----------------------------------+--------+-----------------------------------------+-----------+------------+------+------------+
    | http://localhost:9311/v1/secrets/bb3d8c20-8ea5-4bfc-9645-c8da79c8b371 | None | 2015-04-15 20:37:37.501475+00:00 | ACTIVE | {'default': 'application/octet-stream'} | aes       |        256 | cbc  | None       |
    +-----------------------------------------------------------------------+------+----------------------------------+--------+-----------------------------------------+-----------+------------+------+------------+

Secret Consumers
----------------

.. code-block:: bash

    $ barbican secret consumer <action>

A subcommand describing the action to be performed should follow. The
subcommands are mostly the same as for container consumers, although
some optional arguments might not apply.

For all subcommands, the secret URI must be specified.
Subcommand actions that a user can take for secret consumers are:

.. code-block:: bash

    secret consumer create  Create a secret consumer.
    secret consumer delete  Delete a secret consumer
    secret consumer list    List consumers of a secret.

The help message for **list** can be seen below.

.. code-block:: bash

    $ barbican help secret consumer list
    usage: barbican secret consumer list [-h] [-f {csv,json,table,value,yaml}] [-c COLUMN]
                                         [--quote {all,minimal,none,nonnumeric}] [--noindent]
                                         [--max-width <integer>] [--fit-width] [--print-empty]
                                         [--sort-column SORT_COLUMN]
                                         [--sort-ascending | --sort-descending] [--limit LIMIT]
                                         [--offset OFFSET]
                                         URI

    List consumers of a secret.

    positional arguments:
    URI           The URI reference for the secret

    optional arguments:
    -h, --help          show this help message and exit
    --limit LIMIT, -l LIMIT
                        specify the limit to the number of items to list per page
                        (default: 10; maximum: 100)
    --offset OFFSET, -o OFFSET
                        specify the page offset (default: 0)

    output formatters:
    output formatter options

    -f {csv,json,table,value,yaml}, --format {csv,json,table,value,yaml}
                        the output format, defaults to table
    -c COLUMN, --column COLUMN
                        specify the column(s) to include, can be repeated to show multiple columns
    --sort-column SORT_COLUMN
                        specify the column(s) to sort the data (columns specified first have a
                        priority, non-existing columns are ignored), can be repeated
    --sort-ascending    sort the column(s) in ascending order
    --sort-descending   sort the column(s) in descending order

    CSV Formatter:
    --quote {all,minimal,none,nonnumeric}
                        when to include quotes, defaults to nonnumeric

    json formatter:
    --noindent          whether to disable indenting the JSON

    table formatter:
    --max-width <integer>
                        Maximum display width, <1 to disable. You can also use the CLIFF_MAX_TERM_WIDTH
                        environment variable, but the parameter takes precedence.
    --fit-width         Fit the table to the display width. Implied if --max-width greater than 0.
                        Set the environment variable CLIFF_FIT_WIDTH=1 to always enable
    --print-empty       Print empty table if there is no data to show.

Secret Consumer Create
----------------------

.. code-block:: bash

    $ barbican secret consumer create --service-type-name image \
                                      --resource-type image \
                                      --resource-id 123e4567-e89b-12d3-a456-426614174002 \
                                      0207414d-c23b-47f6-9cef-f44e907ac7a8

Consumers are uniquely defined by the three attributes (service, resource_type, resource_id).
It is not possible to add a second consumer with exactly the same attributes. The CLI will not
throw any error message If the creation of a new consumer with all the three same attributes
of an existent consumer is attempted. However, the new consumer will not be actually created.

Secret Consumer List
--------------------

.. code-block:: bash

    $ barbican secret consumer list 0207414d-c23b-47f6-9cef-f44e907ac7a8
    +--------------+---------------+--------------------------------------+---------------------+
    | Service      | Resource type | Resource id                          | Created             |
    +--------------+---------------+--------------------------------------+---------------------+
    | image        | image         | 123e4567-e89b-12d3-a456-426614174002 | 2023-01-30T15:54:10 |
    +--------------+---------------+--------------------------------------+---------------------+

Secret Consumer Delete
----------------------

.. code-block:: bash

    $ barbican secret consumer delete --service-type-name image \
                                      --resource-type image \
                                      --resource-id 123e4567-e89b-12d3-a456-426614174002 \
                                      0207414d-c23b-47f6-9cef-f44e907ac7a8

To delete a secret consumer, all three attributes must be provided. Attempting to delete
a non-existing consumer will cause the CLI to throw the following error message:
``Not Found: Consumer not found.``

ACLS
----

.. code-block:: bash

    $ barbican acl <action>

A subcommand describing the action to be performed should follow. The
subcommands are mostly the same for secret and container ACLs.

Subcommand actions that a user can take for ACLs are:

.. code-block:: bash

    acl delete          Delete ACLs for a secret or container as identified by its href.
    acl get             Retrieve ACLs for a secret or container by providing its href.
    acl submit          Submit ACL on a secret or container as identified by its href.
    acl user add        Add ACL users to a secret or container as identified by its href.
    acl user remove     Remove ACL users from a secret or container as identified by its href.

ACL **get** or **delete** subcommand, only takes secret or container href. All
other ACL commands take additional arguments to specify ACL settings data.
Please see help message for both cases of argument. Either secret ref or
container ref is required for all of acl actions.

.. code-block:: bash

    $ barbican help acl get
    usage: barbican acl get [-h] [-f {csv,table,value}] [-c COLUMN]
                            [--max-width <integer>]
                            [--quote {all,minimal,none,nonnumeric}]
                            URI

    Retrieve ACLs for a secret or container by providing its href.

    positional arguments:
      URI                   The URI reference for the secret or container.

    optional arguments:
      -h, --help            show this help message and exit

    output formatters:
      output formatter options

      -f {csv,table,value}, --format {csv,table,value}
                            the output format, defaults to table
      -c COLUMN, --column COLUMN
                            specify the column(s) to include, can be repeated

    table formatter:
      --max-width <integer>
                            Maximum display width, 0 to disable

    CSV Formatter:
      --quote {all,minimal,none,nonnumeric}
                            when to include quotes, defaults to nonnumeric


Following is snippet of related command line options for an ACL modify action
e.g. submit, add or remove.


.. code-block:: bash

    $ barbican help acl submit/user add/user remove
    usage: barbican acl submit [-h] [-f {csv,table,value}] [-c COLUMN]
                               [--max-width <integer>]
                               [--quote {all,minimal,none,nonnumeric}]
                               [--user [USER]]
                               [--project-access | --no-project-access]
                               [--operation-type {read}]
                               URI

    ....
    ....

    positional arguments:
      URI                   The URI reference for the secret or container.

    optional arguments:
      -h, --help            show this help message and exit
      --user [USER], -u [USER]
                            Keystone userid(s) for ACL.
      --project-access      Flag to enable project access behavior.
      --no-project-access   Flag to disable project access behavior.
      --operation-type {read}, -o {read}
                            Type of Barbican operation ACL is set for
    ....
    ....


.. note::

    Default for ``operation-type`` argument is 'read' as that's the only operation
    currently supported by Barbican ACL API. So this argument can be skipped in
    CLI call.


ACLs Get
~~~~~~~~

To get complete ACL setting for a secret or container, use this ACL action.

.. code-block:: bash

    $ barbican acl get http://localhost:9311/v1/secrets/7776adb8-e865-413c-8ccc-4f09c3fe0213

    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | Operation Type | Project Access | Users                                                                    | Created                          | Updated                          | Secret ACL Ref                                                            |
    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | read           | False          | ['721e27b8505b499e8ab3b38154705b9e', '2d0ee7c681cc4549b6d76769c320d91f'] | 2015-07-21 17:52:01.729370+00:00 | 2015-07-28 02:08:02.455276+00:00 | http://localhost:9311/v1/secrets/7776adb8-e865-413c-8ccc-4f09c3fe0213/acl |
    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+

    $ barbican acl get http://localhost:9311/v1/containers/83c302c7-86fe-4f07-a277-c4962f121f19

    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+
    | Operation Type | Project Access | Users                                | Created                          | Updated                          | Container ACL Ref                                                            |
    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+
    | read           | False          | ['2d0ee7c681cc4549b6d76769c320d91f'] | 2015-07-28 01:36:55.791381+00:00 | 2015-07-28 02:05:41.175386+00:00 | http://localhost:9311/v1/containers/83c302c7-86fe-4f07-a277-c4962f121f19/acl |
    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+


Secret or container ref is required. If missing, it will result in error.

.. code-block:: bash

    $ barbican acl get

    usage: barbican acl get [-h] [-f {csv,table,value}] [-c COLUMN]
                            [--max-width <integer>]
                            [--quote {all,minimal,none,nonnumeric}]
                            URI
    barbican acl get: error: too few arguments


ACLs Submit
~~~~~~~~~~~

To submit complete ACL setting for a secret or container, use this ACL action.

.. code-block:: bash

    $ barbican acl submit --user 2d0ee7c681cc4549b6d76769c320d91f --user 721e27b8505b499e8ab3b38154705b9e http://localhost:9311/v1/secrets/7776adb8-e865-413c-8ccc-4f09c3fe0213

    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | Operation Type | Project Access | Users                                                                    | Created                          | Updated                          | Secret ACL Ref                                                            |
    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | read           | True           | ['721e27b8505b499e8ab3b38154705b9e', '2d0ee7c681cc4549b6d76769c320d91f'] | 2015-07-21 17:52:01.729370+00:00 | 2015-08-12 09:53:20.225971+00:00 | http://localhost:9311/v1/secrets/7776adb8-e865-413c-8ccc-4f09c3fe0213/acl |
    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+


If ``user`` argument is missing or has no value, then empty list is passed for
users and this approach can be used to remove existing ACL users. If project
access argument is not provided, then by default project access is enabled. To
disable project access behavior, just pass ``no-project-access`` argument
without any value.

.. code-block:: bash

    $ barbican acl submit --user --no-project-access http://localhost:9311/v1/secrets/7776adb8-e865-413c-8ccc-4f09c3fe0213

    +----------------+----------------+-------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | Operation Type | Project Access | Users | Created                          | Updated                          | Secret ACL Ref                                                            |
    +----------------+----------------+-------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | read           | False          | []    | 2015-07-21 17:52:01.729370+00:00 | 2015-08-12 09:55:23.043433+00:00 | http://localhost:9311/v1/secrets/7776adb8-e865-413c-8ccc-4f09c3fe0213/acl |
    +----------------+----------------+-------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+

    $ barbican acl submit --user 2d0ee7c681cc4549b6d76769c320d91f --no-project-access http://localhost:9311/v1/containers/83c302c7-86fe-4f07-a277-c4962f121f19

    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+
    | Operation Type | Project Access | Users                                | Created                          | Updated                          | Container ACL Ref                                                            |
    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+
    | read           | False          | ['2d0ee7c681cc4549b6d76769c320d91f'] | 2015-07-29 22:01:00.878270+00:00 | 2015-08-19 05:56:09.930302+00:00 | http://localhost:9311/v1/containers/83c302c7-86fe-4f07-a277-c4962f121f19/acl |
    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+

Following error is returned when both mutually exclusive flags are passed.

.. code-block:: bash

    $ barbican acl submit --project-access --no-project-access http://localhost:9311/v1/secrets/7776adb8-e865-413c-8ccc-4f09c3fe0213
    usage: barbican acl submit [-h] [-f {csv,table,value}] [-c COLUMN]
                               [--max-width <integer>]
                               [--quote {all,minimal,none,nonnumeric}]
                               [--user [USER]]
                               [--project-access | --no-project-access]
                               [--operation-type {read}]
                               URI
    barbican acl submit: error: argument --no-project-access: not allowed with argument --project-access


ACL Add User(s)
~~~~~~~~~~~~~~~

To add ACL users for a secret or container, use this ACL action.

If ``user`` argument is missing or has no value, then no change is made in ACL
users. If project access argument is not provided, then no change is made in
existing project access behavior flag.

.. code-block:: bash

    $ barbican acl user add --user c1d20e4b7e7d4917aee6f0832152269b http://localhost:9311/v1/containers/83c302c7-86fe-4f07-a277-c4962f121f19

    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+
    | Operation Type | Project Access | Users                                                                    | Created                          | Updated                          | Container ACL Ref                                                            |
    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+
    | read           | False          | ['2d0ee7c681cc4549b6d76769c320d91f', 'c1d20e4b7e7d4917aee6f0832152269b'] | 2015-07-29 22:01:00.878270+00:00 | 2015-08-12 10:08:19.129370+00:00 | http://localhost:9311/v1/containers/83c302c7-86fe-4f07-a277-c4962f121f19/acl |
    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+------------------------------------------------------------------------------+

.. code-block:: bash

    # Added 2 users for secret (084c2098-66db-4401-8348-d969be0eddaa) earlier via set action.
    $ barbican acl user add --user --no-project-access http://localhost:9311/v1/secrets/084c2098-66db-4401-8348-d969be0eddaa

    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | Operation Type | Project Access | Users                                                                    | Created                          | Updated                          | Secret ACL Ref                                                            |
    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | read           | False          | ['721e27b8505b499e8ab3b38154705b9e', '2d0ee7c681cc4549b6d76769c320d91f'] | 2015-08-12 10:09:27.564371+00:00 | 2015-08-12 10:11:09.749980+00:00 | http://localhost:9311/v1/secrets/084c2098-66db-4401-8348-d969be0eddaa/acl |
    +----------------+----------------+--------------------------------------------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+


ACL Remove User(s)
~~~~~~~~~~~~~~~~~~

To remove ACL users for a secret or container, use this ACL action.

If ``user`` argument is missing or has no value, then no change is made in ACL
users. If project access argument is not provided, then no change is made in
existing project access behavior flag.

If provided userid(s) does not exist in ACL, it is simply ignored and only
existing userid(s) are removed from ACL.

.. code-block:: bash

    $ barbican acl user remove --user 2d0ee7c681cc4549b6d76769c320d91f --user invalid_user_id http://localhost:9311/v1/secrets/084c2098-66db-4401-8348-d969be0eddaa

    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | Operation Type | Project Access | Users                                | Created                          | Updated                          | Secret ACL Ref                                                            |
    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+
    | read           | False          | ['721e27b8505b499e8ab3b38154705b9e'] | 2015-08-12 10:09:27.564371+00:00 | 2015-08-12 10:12:21.842888+00:00 | http://localhost:9311/v1/secrets/084c2098-66db-4401-8348-d969be0eddaa/acl |
    +----------------+----------------+--------------------------------------+----------------------------------+----------------------------------+---------------------------------------------------------------------------+


ACLs Delete
~~~~~~~~~~~

To delete existing ACL setting for a secret or container, use this ACL action.

.. code-block:: bash

    $ barbican acl delete http://localhost:9311/v1/secrets/084c2098-66db-4401-8348-d969be0eddaa

    $ barbican acl get http://localhost:9311/v1/secrets/084c2098-66db-4401-8348-d969be0eddaa

    +----------------+----------------+-------+---------+---------+---------------------------------------------------------------------------+
    | Operation Type | Project Access | Users | Created | Updated | Secret ACL Ref                                                            |
    +----------------+----------------+-------+---------+---------+---------------------------------------------------------------------------+
    | read           | True           | []    | None    | None    | http://localhost:9311/v1/secrets/084c2098-66db-4401-8348-d969be0eddaa/acl |
    +----------------+----------------+-------+---------+---------+---------------------------------------------------------------------------+
