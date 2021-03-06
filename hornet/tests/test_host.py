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

import gevent.monkey
import paramiko

gevent.monkey.patch_all()

import os
import shutil
import unittest
import tempfile

import hornet
from hornet.main import Hornet
from hornet.common.helpers import get_random_item


class HornetTests(unittest.TestCase):
    def setUp(self):
        self.working_dir = tempfile.mkdtemp()
        test_config = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
        shutil.copyfile(test_config, os.path.join(self.working_dir, 'config.json'))

    def tearDown(self):
        shutil.rmtree(self.working_dir)

    def test_ip_assignment(self):
        """
            Tests whether IP addresses are assigned to each host.
        """

        def check_ipv4(value):
            parts = value.split('.')
            if len(parts) == 4 and all(x.isdigit() for x in parts):
                numbers = list(int(x) for x in parts)
                return all(0 <= num < 256 for num in numbers)
            return False

        honeypot = Hornet(self.working_dir)

        for hostname, host in honeypot.vhosts.iteritems():
            self.assertTrue(check_ipv4(host.ip_address))

    def test_default_welcome_message(self):
        """
            Tests whether a virtual host loads a default welcome message
        """
        honeypot = Hornet(self.working_dir)
        for ip, host in honeypot.vhosts.iteritems():
            self.assertTrue(host.welcome.startswith('Welcome to '))

    def test_custom_welcome_message(self):

        honeypot = Hornet(self.working_dir)
        random_host = get_random_item(honeypot.vhosts)
        random_host.filesystem.makedir('/etc')
        with random_host.filesystem.open('/etc/motd', 'w') as motd_file:
            motd_file.write(u'TestingCustomWelcomeMessage')
        self.assertEquals(random_host.welcome, u'TestingCustomWelcomeMessage')

    def test_shell_set_host(self):
        """ Tests if host related attributes are set on the shell properly """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        while honeypot.server.server_port == 0:  # wait until the server is ready
            gevent.sleep(0)
        port = honeypot.server.server_port
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # If we log in properly, this should raise no errors
        client.connect('127.0.0.1', port=port, username='testuser', password='testpassword')
        channel = client.invoke_shell()

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        welcome = ''
        while channel.recv_ready():
            welcome += channel.recv(1)
        lines = welcome.split('\r\n')
        prompt = lines[-1]
        username, remaining = prompt.split('@')
        self.assertEquals(username, 'testuser')
        hostname, remaining = remaining.split(':')
        self.assertEquals(hostname, 'test02')
        self.assertTrue(prompt.endswith('$ '))
        honeypot.stop()
