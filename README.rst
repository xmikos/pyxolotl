Pyxolotl
========

Send and receive messages encrypted with `Axolotl (Double Ratchet) <https://github.com/trevp/double_ratchet/wiki>`_ protocol

Description
-----------

Pyxolotl allows you to send and receive secure end-to-end encrypted messages with 
`perfect forward and future secrecy <https://whispersystems.org/blog/advanced-ratcheting/>`_ over
any channel (email, IM, IRC, Twitter, Hangouts, Facebook, etc.). It uses same
`Axolotl (Double Ratchet) <https://github.com/trevp/double_ratchet/wiki>`_ protocol as Signal
messaging app by Open Whisper Systems.

Protocol
--------

Actual wire protocol is described
`here <https://github.com/xmikos/pyxolotl/wiki/ProtocolV2>`_. Headers
(for differentiating between standard message and key exchange message) are obfuscated
with 100000 iterations of PBKDF2 (with whole encrypted message used as salt). This should make
identifying Pyxolotl messages very resource-intensive to impede mass surveillance or filtering.

Key exchange
------------

Pyxolotl is serverless, all messages are sent P2P, so it doesn't use
`prekeys <https://whispersystems.org/blog/asynchronous-security/>`_. You must first send initial key
exchange message to recipient and wait for his reply before sending actual message (this is same as
`SMS Transport <https://github.com/xmikos/pyxolotl/wiki/ProtocolV2#keyexchangemessage-sms-transport-only>`_
in older versions of TextSecure and in SMSSecure / Silence). Once this initial key exchange is completed,
both parties can send messages to each other without any other inconveniences. Security model is
`TOFU <https://en.wikipedia.org/wiki/Trust_on_first_use>`_ (Trust On First Use), both parties
should compare public keys via independent secure channel to mitigate potential MITM attack during
initial key exchange.

Transports
----------

Pyxolotl have pluggable transports. For now there is only *plaintext* transport (which prints
encoded messages to terminal) and *email* transport (messages are encoded to / decoded from
well-formed MIME emails).

Encodings
---------

Encrypted messages can use different transport encodings. For now there is standard *Base64*
encoding (without padding) and as a curiosity *mnemonic* encoding (based on
`BIP-0039: Mnemonic code for generating deterministic keys <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>`_
which encodes encrypted messages as a sequence of words). Mnemonic encoding is inefficient
(messages are about 3.5x larger than Base64), but it can add another layer of obfuscation against
mass surveillance or filtering.

Local encryption
----------------

Local database (private key, sessions, etc.) is encrypted with AES-CBC using 256-bit key derived
from passphrase (with 100000 iterations of PBKDF2 and random salt) and authenticated with HMAC-SHA256.

Requirements
------------

- Python >= 3.3
- enum (https://pypi.python.org/pypi/enum) for Python < 3.4
- python-axolotl (https://github.com/tgalal/python-axolotl)
- python-axolotl-curve25519 (https://github.com/tgalal/python-axolotl-curve25519)
- protobuf (https://github.com/google/protobuf) >= 2.6
- pycrypto (https://github.com/dlitz/pycrypto)

Usage
-----

Run ``pyxolotl --help`` to see all available options.

Help
----
::

    usage: pyxolotl [-h] [-d] [-t {plaintext,email}] [-e {base64,mnemonic}]
                    [--log LOG] [--db DB] [--config CONFIG] [--version]
                    [-a ADDRESS] [-s SUBJECT]
                    {list,ls,send,receive,recv,exchange,delete,del,rm,passwd} ...
    
    send and receive messages encrypted with Axolotl protocol
    
    optional arguments:
      -h, --help            show this help message and exit
      -d, --debug           log detailed debugging messages (default: False)
      -t {plaintext,email}, --transport {plaintext,email}
                            choose message transport (default: plaintext)
      -e {base64,mnemonic}, --encoder {base64,mnemonic}
                            choose message encoding (default: base64)
      --log LOG             log file path (default:
                            ~/.local/share/pyxolotl/pyxolotl.log)
      --db DB               database file path (default:
                            ~/.local/share/pyxolotl/pyxolotl.db)
      --config CONFIG       configuration file path (default:
                            ~/.local/share/pyxolotl/pyxolotl.json)
      --version             show program's version number and exit
    
    email transport:
      -a ADDRESS, --address ADDRESS
                            your own email address (default: None)
      -s SUBJECT, --subject SUBJECT
                            subject of sent emails (default: None)
    
    commands:
      run `pyxolotl COMMAND --help` to see help message for specific command
    
      {list,ls,send,receive,recv,exchange,delete,del,rm,passwd}
                            available commands
        list (ls)           list known identities
        send                send message to recipient
        receive (recv)      receive message from sender
        exchange            start initial key exchage with recipient
        delete (del, rm)    end session with recipient
        passwd              change passphrase to local storage

Todo:
-----

- write more transports (especially Google Hangouts, Twitter Direct Messages, Facebook Messenger,
  IRC and XMPP)
- make email transport more complete (sending with SMTP, receiving with IMAP IDLE)
- create IM-like console UI (with ``asyncio`` and `Urwid <http://urwid.org/>`_)
- create IM-like Qt 5/QML based GUI
- add support for multiple devices
- add support for group messages
- add support for verifying identity with question (using
  `socialist millionaire <https://en.wikipedia.org/wiki/Socialist_millionaire>`_ protocol)

Example
-------
::

    [alice@nsa.gov ~]$ pyxolotl exchange bob
      SEND:
      To: bob
      Encrypted message: 4uJ8zyMIwSgSIQUuLKlC8WdspRietP45P6nFU6/50wT4cQYxNw4vvqKLHxohBYLC5sDLZ78syjQIMf9PA+3Q9MGootUvOajaZA3thspDIiEF6sSiWxB6l0B4oE7gcMl1T3W+hzI548U46cYrR5KUjXY
    
    [bob@fsb.ru ~]$ pyxolotl receive
      RECEIVE:
      From: alice
      Encrypted message: 4uJ8zyMIwSgSIQUuLKlC8WdspRietP45P6nFU6/50wT4cQYxNw4vvqKLHxohBYLC5sDLZ78syjQIMf9PA+3Q9MGootUvOajaZA3thspDIiEF6sSiWxB6l0B4oE7gcMl1T3W+hzI548U46cYrR5KUjXY
      
      Received initial key exchange request! Send this reply to complete key exchange:
      SEND:
      To: alice
      Encrypted message: 0yx89TMIwigSIQVN+wtEio0h+Zx7WPcIwM9WreOy0r7eETBclhOtDAvANhohBb4qfe8R05/167DQDdd2Gqp5OrxAPcriwJMtzi+2b7QrIiEFhfVGHlCm6b1SX36V1HeFX4pAeW15v1aLb2nGi57NZFAqQD3rKGjPDCCm1Kj6i8GUnf4MAc56fhRIYhUJH2mSvlcSAl2XotmR2Yz2lY0wa7TW1JnmUX+YBbIEgIHk0gQ9Log

    [alice@nsa.gov ~]$ pyxolotl receive
      RECEIVE:
      From: bob
      Encrypted message: 0yx89TMIwigSIQVN+wtEio0h+Zx7WPcIwM9WreOy0r7eETBclhOtDAvANhohBb4qfe8R05/167DQDdd2Gqp5OrxAPcriwJMtzi+2b7QrIiEFhfVGHlCm6b1SX36V1HeFX4pAeW15v1aLb2nGi57NZFAqQD3rKGjPDCCm1Kj6i8GUnf4MAc56fhRIYhUJH2mSvlcSAl2XotmR2Yz2lY0wa7TW1JnmUX+YBbIEgIHk0gQ9Log
      
      Initial key exchange completed!

    [alice@nsa.gov ~]$ pyxolotl ls
      Your public key: 05eac4a25b107a974078a04ee070c9754f75be873239e3c538e9c62b4792948d76
      Existing sessions:
        Identity: bob, Pending key exchange: False
          Public key: 0585f5461e50a6e9bd525f7e95d477855f8a40796d79bf568b6f69c68b9ecd6450

    [bob@fsb.ru ~]$ pyxolotl ls
      Your public key: 0585f5461e50a6e9bd525f7e95d477855f8a40796d79bf568b6f69c68b9ecd6450
      Existing sessions:
        Identity: alice, Pending key exchange: False
          Public key: 05eac4a25b107a974078a04ee070c9754f75be873239e3c538e9c62b4792948d76

    [alice@nsa.gov ~]$ pyxolotl send bob
      Message: Hello Bob!
      SEND:
      To: bob
      Encrypted message: a74TljMKIQWJl7sz1bTEIhF/7nwKBLRi7XeEpzcur7t/MOixAOfbHRAAGAAiEEgco7NQXppy/qsm5TdJllpW+nTQ1QjVsQ

    [bob@fsb.ru ~]$ pyxolotl receive
      RECEIVE:
      From: alice
      Encrypted message: a74TljMKIQWJl7sz1bTEIhF/7nwKBLRi7XeEpzcur7t/MOixAOfbHRAAGAAiEEgco7NQXppy/qsm5TdJllpW+nTQ1QjVsQ
      
      DECRYPTED:
      Hello Bob!

    [bob@fsb.ru ~]$ pyxolotl send alice
      Message: Hello Alice!
      SEND:
      To: alice
      Encrypted message: Zd/HKjMKIQXLGyTr5AcvrpUhfR2H7bYqLXqVy7GpE84VvFFkm1LDbxAAGAAiEJDC8/kM59yVzNeCBtjDVOe1CHWuFDbhYg

    [alice@nsa.gov ~]$ pyxolotl receive
      RECEIVE:
      From: bob
      Encrypted message: Zd/HKjMKIQXLGyTr5AcvrpUhfR2H7bYqLXqVy7GpE84VvFFkm1LDbxAAGAAiEJDC8/kM59yVzNeCBtjDVOe1CHWuFDbhYg
      
      DECRYPTED:
      Hello Alice!

