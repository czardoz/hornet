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
from hornet.core.handler import SSHWrapper
from hornet.common.config import Config
from hornet.core.host import VirtualHost

logger = logging.getLogger(__name__)


class Hornet(object):

    def __init__(self, working_directory):
        self.server = None
        self.handler = None
        self.server_greenlet = None
        self.sessions = {}
        self.working_directory = working_directory
        self.config = self._load_config()

        # Create virtual hosts
        self.vhosts = self._create_vhosts()

    def _load_config(self):
        config_path = os.path.join(self.working_directory, 'config.json')
        if not os.path.isfile(config_path):
            source = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
            destination = config_path
            logger.info('Config file {} not found, copying default'.format(destination))
            shutil.copyfile(src=source, dst=destination)
        with open(config_path, 'r') as config_fp:
            config_params = json.load(config_fp)
            return Config(config_params)

    def _create_vhosts(self):

        # Create a directory for virtual filesystems, if it doesn't exist
        vhosts_path = os.path.join(self.working_directory, 'vhosts')
        if not os.path.isdir(vhosts_path):
            logger.info('Creating directory {} for virtual host filesystems'.format(vhosts_path))
            os.mkdir(vhosts_path)

        hosts = {}
        for host_params in self.config.vhost_params:
            h = VirtualHost(host_params, self.config.network, vhosts_path)
            hosts[h.ip_address] = h
        return hosts

    def start(self):
        self.handler = SSHWrapper(self.vhosts, self.sessions, self.config, self.working_directory)
        self.server = gevent.server.StreamServer((self.config.host, self.config.port),
                                                 handle=self.handler.handle_session)
        self.server_greenlet = gevent.spawn(self.server.serve_forever)
        while self.server.server_port == 0:
            gevent.sleep(0)  # Bad way of waiting, but can't think of anything right now.
        logger.info('SSH server listening on {}:{}'.format(self.server.server_host, self.server.server_port))
        return self.server_greenlet

    def stop(self):
        logging.debug('Stopping the server')
        self.server.stop()
