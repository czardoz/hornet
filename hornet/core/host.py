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
import os


class VirtualHost(object):

    def __init__(self, params, network):
        self.ip_address = str(random.choice(list(network[1:-1])))
        self.hostname = params['hostname']
        self.valid_logins = params['valid_logins']
        self.file_system_dir = os.path.join('vhosts', '{}_{}'.format(self.hostname, self.ip_address))
        # Create a filesystem for this host, if it already doesn't exist
        if not os.path.isdir(self.file_system_dir):
            logging.info('Filesystem for {} does not exist, creating {}'.format(self.hostname, self.file_system_dir))
            os.mkdir(self.file_system_dir)
