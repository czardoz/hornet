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

import gevent.monkey
gevent.monkey.patch_all()

import os
import shutil
import unittest
import tempfile
import paramiko

import hornet
from hornet.main import Hornet


class HornetTests(unittest.TestCase):

    def setUp(self):
        self.working_dir = tempfile.mkdtemp()
        test_config = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
        shutil.copyfile(test_config, os.path.join(self.working_dir, 'config.json'))

    def tearDown(self):
        shutil.rmtree(self.working_dir)

    def test_config_loading(self):
        """ Tests whether Hornet can properly load a configuration file"""

        honeypot = Hornet(self.working_dir)
        self.assertEquals(honeypot.config.host, '127.0.0.1')
        self.assertEquals(honeypot.config.port, 0)
        self.assertEquals(honeypot.config.default_hostname, 'test02')
        self.assertEquals(len(honeypot.config.vhost_params), 3)

    def test_vfs_creation(self):
        """ Tests whether virtual file systems for each host are created """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        vfs_dir = os.path.join(self.working_dir, 'vhosts')
        self.assertTrue(os.path.isdir(vfs_dir))
        for item in os.listdir(vfs_dir):
            self.assertTrue(item.startswith('test'))
        honeypot.stop()

    def test_key_creation(self):
        """ Tests if key file is generated on run """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        while honeypot.server.server_port == 0:  # wait until the server is ready
            gevent.sleep(0)
        port = honeypot.server.server_port
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('127.0.0.1', port=port, username='testuser', password='testpassword')
        # Add a sleep here if this test fails for no reason... the server needs time to write the key file
        # gevent.sleep(1)
        self.assertTrue(os.path.isfile(os.path.join(self.working_dir, 'test_server.key')))
        honeypot.stop()

    def test_login_success(self):
        """ Tests whether an SSH client can login to the Honeypot """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        while honeypot.server.server_port == 0:  # wait until the server is ready
            gevent.sleep(0)
        port = honeypot.server.server_port
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # If we log in properly, this should raise no errors
        client.connect('127.0.0.1', port=port, username='testuser', password='testpassword')
        gevent.sleep(1)
        honeypot.stop()

    def test_login_failure(self):
        """ Tests whether an SSH client login fails on bad credentials """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        while honeypot.server.server_port == 0:  # wait until the server is ready
            gevent.sleep(0)
        port = honeypot.server.server_port
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with self.assertRaises(paramiko.AuthenticationException):
            client.connect('127.0.0.1', port=port, username='aksjd', password='asjdhkasd')
        gevent.sleep(1)
        honeypot.stop()

    def test_vhost_creation(self):
        """ Tests whether virtual hosts are created properly """

        honeypot = Hornet(self.working_dir)
        self.assertEquals(len(honeypot.vhosts), 3)
        default = None
        for hostname, host in honeypot.vhosts.iteritems():
            if host.default:
                default = host
        self.assertFalse(default is None)
