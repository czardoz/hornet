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

import json
import logging
import os
import shutil
import gevent.server

import hornet
from hornet.core.handler import SSHHandler
from hornet.common.config import Config
from hornet.core.host import VirtualHost


class Hornet(object):

    def __init__(self, config_file):
        self.server = None
        self.handler = None
        self.server_greenlet = None
        self.sessions = {}
        self.config_path = config_file
        self.config = self._load_config()
        # Create a virtual hosts directory, if it doesn't exist
        if not os.path.isdir('vhosts'):
            logging.info('Creating a directory for virtual host data.')
            os.mkdir('vhosts')
        self.vhosts = self._create_vhosts()

    def _load_config(self):
        if not os.path.isfile(self.config_path):
            source = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
            destination = self.config_path
            logging.info('Config file {} not found, copying default'.format(destination))
            shutil.copyfile(src=source, dst=destination)
        with open(self.config_path, 'r') as config_fp:
            config_params = json.load(config_fp)
            return Config(config_params)

    def _create_vhosts(self):
        hosts = {}
        for host_params in self.config.vhost_params:
            h = VirtualHost(host_params, self.config.network)
            hosts[h.ip_address] = h
        return hosts

    def start(self):
        self.handler = SSHHandler(self.vhosts, self.sessions)
        self.server = gevent.server.StreamServer((self.config.host, self.config.port),
                                                 handle=self.handler.handle_session)
        self.server_greenlet = gevent.spawn(self.server.serve_forever)
        return self.server_greenlet

