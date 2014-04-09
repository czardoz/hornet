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

import random
import os
from fs.osfs import OSFS


class VirtualHost(object):

    def __init__(self, params, network, fs_dir):
        self.ip_address = str(random.choice(list(network[1:-1])))
        self.hostname = params['hostname']
        self.valid_logins = params['valid_logins']
        self.filesystem = OSFS(os.path.join(fs_dir, '{}_{}'.format(self.hostname, self.ip_address)), create=True)
