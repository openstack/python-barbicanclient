import argparse

from barbicanclient import client


class Keep:
    def __init__(self):
        self.parser = self.get_main_parser()
        self.subparsers = self.parser.add_subparsers(title='subcommands',
                                                     description=
                                                     'Action to perform')
        self.add_create_args()
        self.add_delete_args()
        self.add_get_args()
        self.add_list_args()

    def get_main_parser(self):
        parser = argparse.ArgumentParser(description='Access the Barbican'
                                         ' key management sevice.')
        parser.add_argument('type',
                            choices=["order", "secret"],
                            help="type to operate on")
        parser.add_argument('--auth_endpoint', '-A',
                            default=client.env('OS_AUTH_URL'),
                            help='the URL to authenticate against (default: '
                                 '%(default)s)')
        parser.add_argument('--user', '-U', default=client.env('OS_USERNAME'),
                            help='the user to authenticate as (default: %(de'
                                 'fault)s)')
        parser.add_argument('--password', '-P',
                            default=client.env('OS_PASSWORD'),
                            help='the API key or password to authenticate with'
                            ' (default: %(default)s)')
        parser.add_argument('--tenant', '-T',
                            default=client.env('OS_TENANT_NAME'),
                            help='the tenant ID (default: %(default)s)')
        parser.add_argument('--endpoint', '-E',
                            default=client.env('BARBICAN_ENDPOINT'),
                            help='the URL of the barbican server (default: %'
                            '(default)s)')
        parser.add_argument('--token', '-K',
                            default=client.env('AUTH_TOKEN'), help='the au'
                            'thentication token (default: %(default)s)')
        return parser

    def add_create_args(self):
        create_parser = self.subparsers.add_parser('create', help='Create a '
                                                   'secret or an order')
        create_parser.add_argument('--mime_type', '-m', default='text/plain',
                                   help='the MIME type of the raw secret (defa'
                                   'ult: %(default)s)')
        create_parser.add_argument('--name', '-n', help='a human-friendly name'
                                   ' used only for reference')
        create_parser.add_argument('--algorithm', '-a', help='the algorithm us'
                                   'ed only for reference')
        create_parser.add_argument('--bit_length', '-b', default=256,
                                   help='the bit length of the secret used '
                                   'only for reference (default: %(default)s)',
                                   type=int)
        create_parser.add_argument('--cypher_type', '-c', help='the cypher typ'
                                   'e used only for reference')
        create_parser.add_argument('--plain_text', '-p', help='the unencrypted'
                                   ' secret (only used for secrets)')
        create_parser.add_argument('--expiration', '-e', help='the expiration '
                                   'time for the secret in ISO 8601 format '
                                   '(only used for secrets)')
        create_parser.set_defaults(func=self.create)

    def add_delete_args(self):
        delete_parser = self.subparsers.add_parser('delete', help='Delete a se'
                                                   'cret or an order by provid'
                                                   'ing its UUID')
        delete_parser.add_argument('UUID', help='the universally unique identi'
                                   'fier of the the secret or order')
        delete_parser.set_defaults(func=self.delete)

    def add_get_args(self):
        get_parser = self.subparsers.add_parser('get', help='Retrieve a secret'
                                                ' or an order by providing its'
                                                ' UUID.')
        get_parser.add_argument('UUID', help='the universally unique identi'
                                'fier of the the secret or order')
        get_parser.add_argument('--raw', '-r', help='if specified, gets the ra'
                                'w secret of type specified with --mime_type ('
                                'only used for secrets)', action='store_true')
        get_parser.add_argument('--mime_type', '-m', default='text/plain',
                                help='the MIME type of the raw secret (defa'
                                'ult: %(default)s; only used for secrets)')
        get_parser.set_defaults(func=self.get)

    def add_list_args(self):
        list_parser = self.subparsers.add_parser('list',
                                                 help='List secrets or orders')
        list_parser.add_argument('--limit', '-l', default=10, help='specify t'
                                 'he limit to the number of items to list per'
                                 ' page (default: %(default)s; maximum: 100)',
                                 type=int)
        list_parser.add_argument('--offset', '-o', default=0, help='specify t'
                                 'he page offset (default: %(default)s)',
                                 type=int)
        list_parser.add_argument('--URI', '-u', help='the full reference to '
                                 'what is to be listed; put in quotes to avoid'
                                 ' backgrounding when \'&\' is in the URI')
        list_parser.set_defaults(func=self.lst)

    def create(self, args):
        if args.type == 'secret':
            secret = self.conn.create_secret(args.mime_type,
                                             args.plain_text,
                                             args.name,
                                             args.algorithm,
                                             args.bit_length,
                                             args.cypher_type,
                                             args.expiration)
            print secret
        else:
            order = self.conn.create_order(args.mime_type,
                                           args.name,
                                           args.algorithm,
                                           args.bit_length,
                                           args.cypher_type)
            print order

    def delete(self, args):
        if args.type == 'secret':
            self.conn.delete_secret_by_id(args.UUID)
        else:
            self.conn.delete_order_by_id(args.UUID)

    def get(self, args):
        if args.type == 'secret':
            if args.raw:
                print self.conn.get_raw_secret_by_id(args.UUID, args.mime_type)
            else:
                print self.conn.get_secret_by_id(args.UUID)
        else:
            print self.conn.get_order_by_id(args.UUID)

    def lst(self, args):
        if args.type == 'secret':
            if args.URI:
                l = self.conn.list_secrets_by_href(args.URI)
            else:
                l = self.conn.list_secrets(args.limit, args.offset)
        else:
            if args.URI:
                l = self.conn.list_orders_by_href(args.URI)
            else:
                l = self.conn.list_orders(args.limit, args.offset)
        for i in l[0]:
            print i
        print '{0}s displayed: {1} - offset: {2}'.format(args.type, len(l[0]),
                                                         args.offset)

    def execute(self, **kwargs):
        args = self.parser.parse_args(kwargs.get('argv'))
        self.conn = client.Connection(args.auth_endpoint, args.user,
                                      args.password, args.tenant,
                                      args.token,
                                      endpoint=args.endpoint)

        args.func(args)


def main():
    k = Keep()
    k.execute()


if __name__ == '__main__':
    main()
