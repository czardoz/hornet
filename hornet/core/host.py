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
            logger.error('IP address for {} is not specified in the config file (or is "null")'.format(self.hostname))
            if not self._set_ip_from_previous_run(fs_dir, valid_ips):
                self.ip_address = get_random_item(valid_ips)
                logger.info('Assigned random IP {} to host {}'.format(self.ip_address, self.hostname))
        else:
            if not self.ip_address in valid_ips:
                logger.error('IP Address {} for {} is not valid for the specified network'.format(
                    params['ip_address'], self.hostname))
                if not self._set_ip_from_previous_run(fs_dir, valid_ips):
                    self.ip_address = get_random_item(valid_ips)
                    logger.info('Assigned random IP {} to host {}'.format(self.ip_address, self.hostname))

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

    def login(self, username):
        logger.debug('User "{}" has logged into "{}" host'.format(username, self.hostname))
        self.logged_in = True
        self.current_user = username

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

    def _set_ip_from_previous_run(self, fs_dir, valid_ips):  # pragma: no cover
        for dir_name in os.listdir(fs_dir):
            if dir_name.startswith(self.hostname + '_'):
                possible_ip = dir_name.split('_')[1]
                if possible_ip in valid_ips:
                    self.ip_address = possible_ip
                    logger.info('Assigned IP {} to host {}'.format(self.ip_address, self.hostname))
                    return True
        return False
