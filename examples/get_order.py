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
        description='Testing code for getting a barbican order.'
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
        '--order-id',
        default=None,
        help='ID of order'
    )
    parser.add_argument(
        '--order-href',
        default=None,
        help='href of order'
    )

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()
    conn = connect(args.username, args.password, args.tenant, args.endpoint)
    if args.order_id is not None:
        order = conn.get_order_by_id(args.order_id)
    else:
        order = conn.get_order(args.order_href)
    print order
