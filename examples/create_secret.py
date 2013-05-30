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
        description='Testing code for creating barbican secret.'
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
        '--name',
        help='Name of secret'
    )
    parser.add_argument(
        '--mime-type',
        help='MIME type of secret to create'
    )
    parser.add_argument(
        '--algorithm',
        help='Algorithm of secret to create'
    )
    parser.add_argument(
        '--bit-length',
        help='Bit length of secret to create'
    )
    parser.add_argument(
        '--cypher-type',
        help='Cypher type of secret to create'
    )
    parser.add_argument(
        '--plain-text',
        help='Plain text of the secret'
    )
    parser.add_argument(
        '--expiration',
        default=None,
        help='Plain text of the secret'
    )

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()
    conn = connect(args.username, args.password, args.tenant, args.endpoint)
    secret_ref = conn.create_secret(args.name,
                                    args.mime_type,
                                    args.algorithm,
                                    args.bit_length,
                                    args.cypher_type,
                                    args.plain_text,
                                    args.expiration)
    print secret_ref
