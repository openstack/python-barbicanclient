import argparse

from barbicanclient import client

IDENTITY = 'https://identity.api.rackspacecloud.com/v2.0'
ENDPOINT = 'https://barbican.api.rackspacecloud.com/v1/'


def list_secrets(username, password, tenant, endpoint):
    connection = client.Connection(IDENTITY,
                                   username,
                                   password,
                                   tenant,
                                   endpoint=endpoint)
    secrets = connection.list_secrets()

    print 'Current Secrets ({0}):'.format(len(secrets))
    for secret in secrets:
        print secret


def parse_args():
    parser = argparse.ArgumentParser(
        description='Testing code for barbican secrets api resource.'
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

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()
    list_secrets(args.username, args.password, args.tenant, args.endpoint)
