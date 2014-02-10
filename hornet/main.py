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

import hornet


class Hornet(object):

    def __init__(self):
        self.port = None
        self.server = None
        self.load_config()

    def load_config(self):
        if not os.path.isfile('config.json'):
            source = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
            destination = os.path.join(os.getcwd(), 'config.json')
            logging.debug('Config file not found, copying default'.format(source))
            shutil.copyfile(src=source, dst=destination)
        with open('config.json', 'r') as config_fp:
            config = json.load(config_fp)
        self.port = config['port']

    def start(self):
        pass
