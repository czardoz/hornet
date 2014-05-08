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

import netaddr
import logging

logger = logging.getLogger(__name__)


class Network(netaddr.IPNetwork):
    def __init__(self, addr, dns_server, gateway):
        self.dns_server = dns_server
        self.gateway = gateway
        super(Network, self).__init__(addr)


class Config(object):

    def __init__(self, cdict):
        self.port = cdict['port']
        self.host = cdict['host']
        self.network = Network(cdict['network']['network_ip'],
                               cdict['network']['dns_server'], cdict['network']['gateway'])
        self.num_vhosts = len(cdict['virtual_hosts'])
        self.vhost_params = cdict['virtual_hosts']
        self.key_file = cdict['key_file']

        self.default_hostname = None
        for p in self.vhost_params:
            if p.get('default', False):
                logger.debug('Default host set to: {}'.format(p['hostname']))
                self.default_hostname = p['hostname']
        if self.default_hostname is None:
            logger.info('Default host not found, setting {} to default.'.format(self.vhost_params[0]['hostname']))
            self.default_hostname = self.vhost_params[0]['hostname']
