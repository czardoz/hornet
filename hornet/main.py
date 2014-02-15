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


class Hornet(object):

    handler_class = SSHHandler

    def __init__(self):
        self.host = None
        self.port = None
        self.server = None
        self.handler = None
        self.server_greenlet = None
        self._load_config()

    def _load_config(self):
        if not os.path.isfile('config.json'):
            source = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
            destination = os.path.join(os.getcwd(), 'config.json')
            logging.debug('Config file not found, copying default'.format(source))
            shutil.copyfile(src=source, dst=destination)
        with open('config.json', 'r') as config_fp:
            config = json.load(config_fp)
        self.port = config.get('port', None) or 22
        self.host = config.get('host', None) or '0.0.0.0'

    def start(self):
        self.handler = self.handler_class()
        self.server = gevent.server.StreamServer((self.host, self.port), handle=self.handler.handle_session)
        self.server_greenlet = gevent.spawn(self.server.serve_forever)
        return self.server_greenlet

