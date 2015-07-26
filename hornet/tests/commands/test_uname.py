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
import os

import gevent.monkey
import hornet

gevent.monkey.patch_all()

import paramiko
from hornet.main import Hornet
from hornet.tests.commands.base import BaseTestClass


class HornetTests(BaseTestClass):

    def test_uname(self):
        """ Tests if uname command works """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        self.create_filesystem(honeypot)

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the uname command
        uname_command = 'uname'
        channel.send(uname_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, uname_command)
        self.assertEquals(command_output, 'Linux')
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_uname_with_params(self):
        """ Tests if 'uname -a' command works """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        self.create_filesystem(honeypot)

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the cd command
        uname_command = 'uname -a'
        channel.send(uname_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        expected_info = ['Linux', honeypot.config.default_hostname, '3.13.0-37-generic',
                         '#64-Ubuntu SMP Mon Sep 22 21:30:01 UTC 2014', 'i686',
                         'i686', 'i686', 'GNU/Linux']

        self.assertEquals(command, uname_command)
        self.assertEquals(command_output, ' '.join(expected_info))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_uname_other_params(self):
        """ Tests if 'uname -snrvmpio' works """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        self.create_filesystem(honeypot)

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the uname command
        uname_command = 'uname -snrvmpio'
        channel.send(uname_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        expected_info = ['Linux', honeypot.config.default_hostname, '3.13.0-37-generic',
                         '#64-Ubuntu SMP Mon Sep 22 21:30:01 UTC 2014', 'i686',
                         'i686', 'i686', 'GNU/Linux']

        self.assertEquals(command, uname_command)
        self.assertEquals(command_output, ' '.join(expected_info))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_uname_version_param(self):
        """ Tests if 'uname --version' works """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        self.create_filesystem(honeypot)

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the uname command
        uname_command = 'uname --version'
        channel.send(uname_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        expected_output = []
        version_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                         'commands', 'uname', 'version')
        with open(version_file_path) as version_file:
            for line in version_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, uname_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_uname_help_param(self):
        """ Tests if 'uname --version' works """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        self.create_filesystem(honeypot)

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the uname command
        uname_command = 'uname --help'
        channel.send(uname_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        expected_output = []
        version_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                         'commands', 'uname', 'help')
        with open(version_file_path) as version_file:
            for line in version_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, uname_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()
