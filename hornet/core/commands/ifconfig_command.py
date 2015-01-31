# !/usr/bin/env python
#
# Hornet - SSH Honeypot
#
# Copyright (C) 2015 Aniket Panse <aniketpanse@gmail.com>
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
from string import Template

logger = logging.getLogger(__name__)


class _IfconfigTemplate(object):

    def __init__(self, template_path):
        self.interface_data = {}
        with open(template_path, 'r') as templatefile:
            self.all_template = templatefile.read()
            interfaces = self.all_template.split('\n\n')
            for interface in interfaces:
                first_line = interface.split('\n')[0]
                interface_name = first_line.split()[0]
                self.interface_data[interface_name] = interface

    def interface_exists(self, interface):
        return interface in self.interface_data

    def render(self, iface, network, ip_address):
        mapping = {
            'ip_addr': ip_address,
            'broadcast_addr': network.broadcast,
            'subnet_mask': network.netmask
        }
        template_string = Template(self.interface_data[iface])
        return template_string.safe_substitute(mapping)

    def render_all(self, network, ip_address):
        mapping = {
            'ip_addr': ip_address,
            'broadcast_addr': network.broadcast,
            'subnet_mask': network.netmask
        }
        template_string = Template(self.all_template)
        return template_string.safe_substitute(mapping)


class IfconfigCommand(object):

    def __init__(self, params, template_path, ip_address, network):
        self.params = params
        self.ip_address = ip_address
        self.network = network
        self.template_path = template_path
        self.template = None

    def process(self):
        self.template = _IfconfigTemplate(self.template_path)
        if self.params:
            interface_name = self.params[0]
            if not self.template.interface_exists(interface_name):
                return '{}: error fetching interface information: Device not found'.format(interface_name)
            else:
                return self.template.render(interface_name, self.network, self.ip_address)
        else:
            return self.template.render_all(self.network, self.ip_address)
