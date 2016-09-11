#!/usr/bin/env python
import os, sys, binascii, base64, logging, argparse, getpass

from pyxolotl.version import __version__
from pyxolotl.config import config
from pyxolotl.core import Pyxolotl
from pyxolotl.protocol.basic import Message
from pyxolotl.exceptions import NoSessionException, PendingKeyExchangeException
from pyxolotl.cryptostorage import CryptoStorage

UNENCRYPTED_PASSPHRASE = b'unencrypted'


def user_data_dir(appname=None):
    """Return path to the user data directory for this application"""
    if sys.platform == 'win32':
        path = os.getenv('LOCALAPPDATA', os.path.normpath(os.path.expanduser('~/AppData/Local/')))
        if appname:
            path = os.path.join(path, appname, appname)
    elif sys.platform == 'darwin':
        path = os.path.expanduser('~/Library/Application Support/')
        if appname:
            path = os.path.join(path, appname)
    else:
        path = os.getenv('XDG_DATA_HOME', os.path.expanduser('~/.local/share/'))
        if appname:
            path = os.path.join(path, appname)
    return path


def get_new_passphrase():
    """Ask for new passphrase"""
    passphrase = getpass.getpass('New passphrase (leave empty for no password): ').encode('utf-8')
    if passphrase:
        confirm_passphrase = getpass.getpass('Confirm passphrase: ').encode('utf-8')
        if passphrase != confirm_passphrase:
            print('Passphrases doesn\'t match!', file=sys.stderr)
            sys.exit(1)
        config['encrypted'] = True
    else:
        passphrase = UNENCRYPTED_PASSPHRASE
        config['encrypted'] = False
    config.save()
    return passphrase


def get_cryptostorage():
    """Open existing CryptoStorage or initialize new one"""
    if config['mastersecret']:
        cryptostorage = CryptoStorage(base64.b64decode(config['mastersecret'].encode('utf-8')))
        passphrase = b''
    else:
        cryptostorage = CryptoStorage()
        passphrase = get_new_passphrase()
        cryptostorage.init_storage(passphrase)
        config['mastersecret'] = base64.b64encode(cryptostorage.mastersecret).decode('utf-8')
        config.save()

    if config['encrypted']:
        passphrase = passphrase or getpass.getpass('Passphrase: ').encode('utf-8')
    else:
        passphrase = UNENCRYPTED_PASSPHRASE

    cryptostorage.open_storage(passphrase)
    return cryptostorage


def command_passwd(args):
    if config['mastersecret']:
        cryptostorage = CryptoStorage(base64.b64decode(config['mastersecret'].encode('utf-8')))
        if config['encrypted']:
            passphrase = getpass.getpass('Current passphrase: ').encode('utf-8')
        else:
            passphrase = UNENCRYPTED_PASSPHRASE

        cryptostorage.open_storage(passphrase)
        new_passphrase = get_new_passphrase()
        cryptostorage.change_passphrase(new_passphrase)
        config['mastersecret'] = base64.b64encode(cryptostorage.mastersecret).decode('utf-8')
        config.save()
    else:
        cryptostorage = get_cryptostorage()


def command_list(args):
    axo = Pyxolotl(args.db, cryptostorage=get_cryptostorage())

    your_public_key = axo.store.getIdentityKeyPair().getPublicKey().serialize()
    print('Your public key: {}'.format(binascii.hexlify(your_public_key).decode('ascii')))

    all_sessions = axo.store.sessionStore.getAllSessions()
    if all_sessions:
        print('Existing sessions:')
        for identity, device_id, record in all_sessions:
            try:
                public_key = binascii.hexlify(
                    record.getSessionState().getRemoteIdentityKey().serialize()
                ).decode('ascii')
            except IndexError:
                public_key = 'UNKNOWN'
            print('\tIdentity: {}, Pending key exchange: {}'.format(
                identity.decode('utf-8'),
                record.getSessionState().hasPendingKeyExchange()
            ))
            print('\t\tPublic key: {}'.format(public_key))
    else:
        print('No sessions found.')


def command_send(args):
    axo = Pyxolotl(args.db, cryptostorage=get_cryptostorage())
    transport = args.transport_obj
    message = args.message or input('Message: ')
    try:
        transport.send(axo.send(args.recipient, message))
    except NoSessionException:
        print('Session for recipient "{}" doesn\'t exist! '
              'Send initial key exchange first.'.format(args.recipient),
              file=sys.stderr)
        sys.exit(1)
    except PendingKeyExchangeException:
        print('Session for recipient "{}" is in pending key exchange state! '
              'Wait for key exchange reply first.'.format(args.recipient),
              file=sys.stderr)
        sys.exit(1)


def command_receive(args):
    axo = Pyxolotl(args.db, cryptostorage=get_cryptostorage())
    transport = args.transport_obj
    message = transport.receive(args.encrypted_message)
    decrypted = axo.receive(message)
    if decrypted and isinstance(decrypted, Message):
        print('Received initial key exchange request! '
              'Send this reply to complete key exchange:', file=sys.stderr)
        transport.send(decrypted)
    elif decrypted:
        print('DECRYPTED:')
        print(decrypted)
    else:
        print('Initial key exchange completed!', file=sys.stderr)


def command_exchange(args):
    axo = Pyxolotl(args.db, cryptostorage=get_cryptostorage())
    transport = args.transport_obj
    if not axo.store.containsSession(args.recipient, axo.DEFAULT_DEVICE_ID):
        transport.send(axo.init_key_exchange(args.recipient))
    else:
        print('Session for recipient "{}" already exists!'.format(args.recipient), file=sys.stderr)
        if args.force:
            print('Sending initial key exchange anyway...', file=sys.stderr)
            print(file=sys.stderr)
            transport.send(axo.init_key_exchange(args.recipient))
        else:
            sys.exit(1)


def command_delete(args):
    axo = Pyxolotl(args.db, cryptostorage=get_cryptostorage())
    transport = args.transport_obj
    try:
        transport.send(axo.end_session(args.recipient))
    except NoSessionException:
        print('Session for recipient "{}" doesn\'t exist!'.format(args.recipient), file=sys.stderr)
        sys.exit(1)


def main():
    # Build default paths for files.
    default_log_path = os.path.join(user_data_dir('pyxolotl'), 'pyxolotl.log')
    default_db_path = os.path.join(user_data_dir('pyxolotl'), 'pyxolotl.db')
    default_config_path = os.path.join(user_data_dir('pyxolotl'), 'pyxolotl.json')

    # Setup global command line parser
    parser = argparse.ArgumentParser(
        prog='pyxolotl',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='send and receive messages encrypted with Axolotl (Double Ratchet) protocol'
    )
    parser.add_argument('-d', '--debug', action='store_true',
                        help='log detailed debugging messages')
    parser.add_argument('-t', '--transport', choices=['plaintext', 'email'], default='plaintext',
                        help='choose message transport')
    parser.add_argument('-e', '--encoder', choices=['base64', 'mnemonic'], default='base64',
                        help='choose message encoding')
    parser.add_argument('--log', default=default_log_path,
                        help='log file path')
    parser.add_argument('--db', default=default_db_path,
                        help='database file path')
    parser.add_argument('--config', default=default_config_path,
                        help='configuration file path')
    parser.add_argument('--version', action='version',
                        version='%(prog)s {}'.format(__version__))

    # Argument groups for different transports
    group_email = parser.add_argument_group('email transport')
    group_email.add_argument('-a', '--address',
                             help='your own email address')
    group_email.add_argument('-s', '--subject',
                             help='subject of sent emails')

    # Add subparsers for commands
    subparsers = parser.add_subparsers(dest='command', title='commands',
                                       description=('run `%(prog)s COMMAND --help` to see help '
                                                    'message for specific command'),
                                       help='available commands')

    # List command
    parser_list = subparsers.add_parser('list', aliases=['ls'],
                                        description='list known identities',
                                        help='list known identities')
    parser_list.set_defaults(func=command_list)

    # Send command
    parser_send = subparsers.add_parser('send',
                                        description='send message to recipient',
                                        help='send message to recipient')
    parser_send.add_argument('recipient',
                             help='send message to this identity')
    parser_send.add_argument('message', nargs='?',
                             help='plaintext message')
    parser_send.set_defaults(func=command_send)

    # Receive command
    parser_receive = subparsers.add_parser('receive', aliases=['recv'],
                                           description='receive message from sender',
                                           help='receive message from sender')
    parser_receive.add_argument('encrypted_message', nargs='?',
                                help='encrypted message in form specified by used transport')
    parser_receive.set_defaults(func=command_receive)

    # Exchange command
    parser_exchange = subparsers.add_parser('exchange',
                                            description='start initial key exchange with recipient',
                                            help='start initial key exchage with recipient')
    parser_exchange.add_argument('recipient',
                                 help='send initial key exchange message to this recipient')
    parser_exchange.add_argument('-f', '--force', action='store_true',
                                 help='send key exchange even if session for recipiend already exists')
    parser_exchange.set_defaults(func=command_exchange)

    # Delete command
    parser_delete = subparsers.add_parser('delete', aliases=['del', 'rm'],
                                          description='end session with recipient',
                                          help='end session with recipient')
    parser_delete.add_argument('recipient',
                               help='delete session with this recipient')
    parser_delete.set_defaults(func=command_delete)

    # Change passphrase command
    parser_passwd = subparsers.add_parser('passwd',
                                          description='change passphrase to local storage',
                                          help='change passphrase to local storage')
    parser_passwd.set_defaults(func=command_passwd)

    # Show help if no command is specified
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        parser.exit(1)

    # Create all necessary directories
    for path in [args.log, args.db, args.config]:
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            try:
                os.makedirs(directory)
            except OSError as e:
                parser.exit(1, 'Failed to create directory: {}'.format(e))

    # Setup logging
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(filename=args.log, level=log_level, format=log_format)

    # Setup config
    config.filename = args.config
    config.load()

    # Setup encoder
    if args.encoder == 'base64':
        from pyxolotl.encoder.base64 import Encoder
        encoder = Encoder()
    elif args.encoder == 'mnemonic':
        from pyxolotl.encoder.mnemonic import Encoder
        encoder = Encoder()

    # Setup transport
    if args.transport == 'plaintext':
        from pyxolotl.transport.plaintext import Transport
        args.transport_obj = Transport(encoder=encoder)
    elif args.transport == 'email':
        if not args.address:
            parser.error('you must specify --address/-a option if using email transport')
        from pyxolotl.transport.email import Transport
        args.transport_obj = Transport(address=args.address, subject=args.subject, encoder=encoder)

    # Run command
    if 'func' in args:
        args.func(args)


if __name__ == '__main__':
    main()
