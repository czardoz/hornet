# !/usr/bin/env python
#
# Hornet - SSH Honeypot
#
# Copyright (C) 2014 Aniket Panse <aniketpanse@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import os

from OpenSSL import crypto

logger = logging.getLogger(__name__)


def create_self_signed_cert(directory, cname, kname, cert_country='US', cert_state='state', cert_organization='org',
                            cert_locality='local', cert_organizational_unit='unit', cert_common_name='common name'):
    logger.info('Creating SSL Certificate and Key: {}, {}'.format(cname, kname))
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    sub = cert.get_subject()

    # Later, we'll get these fields from the server
    # country
    sub.C = cert_country
    # state or province name
    sub.ST = cert_state
    # locality
    sub.L = cert_locality
    # organization
    sub.O = cert_organization
    # organizational unit
    sub.OU = cert_organizational_unit
    # common name
    sub.CN = cert_common_name

    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for a year
    cert.set_issuer(sub)
    cert.set_pubkey(pk)
    cert.sign(pk, 'sha1')

    certpath = os.path.join(directory, cname)
    keypath = os.path.join(directory, kname)

    with open(certpath, 'w') as certfile:
        certfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    priv_key_text = crypto.dump_privatekey(crypto.FILETYPE_PEM, pk)

    from Crypto.PublicKey import RSA

    priv_key = RSA.importKey(priv_key_text)
    with open(keypath, 'w') as keyfile:
        keyfile.write(priv_key.exportKey('PEM'))
