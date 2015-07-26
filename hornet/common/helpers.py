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
import random

from paramiko import RSAKey

logger = logging.getLogger(__name__)


def get_rsa_key_file(filename, password=None):
    try:
        key = RSAKey(filename=filename, password=password)
    except IOError:
        logger.info('RSA Key file not found, generating a new one: %s', filename)
        key = RSAKey.generate(1024)
        key.write_private_key_file(filename, password=password)
    return key


def get_random_item(collection):
    if isinstance(collection, dict):
        all_keys = list(collection.keys())
        r = random.choice(all_keys)
        return collection[r]
    elif isinstance(collection, list):
        return random.choice(collection)


# http://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
# By Fred Cicera
def human_readable(num, suffix=''):
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)
