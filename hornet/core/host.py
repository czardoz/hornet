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

from fs.osfs import OSFS
from hornet.common.helpers import get_random_item

logger = logging.getLogger(__name__)


class VirtualHost(object):

    def __init__(self, params, network, fs_dir):
        self.hostname = params['hostname']
        self.ip_address = params['ip_address']
        self.env = params['env']

        valid_ips = map(str, network[1:-1])
        if self.ip_address is None:
            self.ip_address = get_random_item(valid_ips)
        else:
            if not self.ip_address in valid_ips:
                logger.error('IP Address {} for {} is not valid for the specified network, '
                             'assigning random IP'.format(params['ip_address'], self.hostname))
                self.ip_address = get_random_item(valid_ips)
                logger.info('Assigned IP {} to host {}'.format(self.ip_address, self.hostname))

        self.valid_logins = params['valid_logins']
        self.logged_in = False
        self.current_user = None
        if params.get('default', False):
            self.default = True
        else:
            self.default = False
        self.filesystem = OSFS(os.path.join(fs_dir, '{}_{}'.format(self.hostname, self.ip_address)), create=True)
        self.working_path = '~'

    def authenticate(self, username, password):
        if self.valid_logins.get(username, None) == password:
            return True
        return False

    def login(self, username, password):
        if self.authenticate(username, password):
            logger.debug('User "{}" has logged into "{}" host'.format(username, self.hostname))
            self.logged_in = True
            self.current_user = username
            return True
        else:  # pragma: no cover
            logger.debug('User "{}" has tried to login to "{}" host, password was "{}"'.format(username, self.hostname,
                                                                                               password))
            return False

    @property
    def welcome(self):
        if self.filesystem.isfile('/etc/motd'):
            with self.filesystem.open('/etc/motd') as motd_file:
                return motd_file.read()
        else:
            return 'Welcome to {} server.'.format(self.hostname)

    @property
    def prompt(self):
        prompt = '{}@{}:{}$ '.format(self.current_user, self.hostname, self.working_path)
        return prompt

    def run_echo(self, params, shell):
        if not params:
            shell.writeline('')
        elif params[0].startswith('$') and len(params) == 1:
            var_name = params[0][1:]
            value = self.env.get(var_name, '')
            shell.writeline(value)
        elif '*' in params:
            params.remove('*')
            params.extend(self.filesystem.listdir())
            shell.writeline(' '.join(params))
        else:
            shell.writeline(' '.join(params))
