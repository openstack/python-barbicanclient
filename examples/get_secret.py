import argparse

from barbicanclient import client

IDENTITY = 'https://identity.api.rackspacecloud.com/v2.0'
ENDPOINT = 'https://barbican.api.rackspacecloud.com/v1/'


def connect(username, password, tenant, endpoint):
    connection = client.Connection(IDENTITY,
                                   username,
                                   password,
                                   tenant,
                                   endpoint=endpoint)
    return connection


def parse_args():
    parser = argparse.ArgumentParser(
        description='Testing code for getting a barbican secret.'
    )
    parser.add_argument(
        '--username',
        help='The keystone username used for for authentication'
    )
    parser.add_argument(
        '--password',
        help='The keystone password used for for authentication'
    )
    parser.add_argument(
        '--tenant',
        help='The keystone tenant used for for authentication'
    )
    parser.add_argument(
        '--keystone',
        default=IDENTITY,
        help='The keystone endpoint used for for authentication'
    )
    parser.add_argument(
        '--endpoint',
        default=ENDPOINT,
        help='The barbican endpoint to test against'
    )
    parser.add_argument(
        '--secret-id',
        default=None,
        help='ID of secret'
    )
    parser.add_argument(
        '--secret-href',
        default=None,
        help='href of secret'
    )
    parser.add_argument(
        '--mime-type',
        default=None,
        help='MIME of secret'
    )

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()
    conn = connect(args.username, args.password, args.tenant, args.endpoint)
    if args.mime_type is not None:
        if args.secret_id is not None:
            s = conn.get_raw_secret_by_id(args.secret_id, args.mime_type)
        else:
            s = conn.get_raw_secret(args.secret_href, args.mime_type)
    else:
        if args.secret_id is not None:
            s = conn.get_secret_by_id(args.secret_id)
        else:
            s = conn.get_secret(args.secret_href)
    print s
