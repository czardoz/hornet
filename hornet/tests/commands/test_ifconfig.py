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
import hornet

gevent.monkey.patch_all()

import unittest
import paramiko
import os
from hornet.main import Hornet
from hornet.tests.commands.base import BaseTestClass


class HornetTests(BaseTestClass):

    def test_ifconfig(self):
        """ Tests if ifconfig command works """

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
        cd_command = 'ifconfig'
        channel.send(cd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, cd_command)
        interfaces = sorted(command_output.split('\r\n\r\n'))
        self.assertTrue(interfaces[0].startswith('eth0 '))
        self.assertTrue('HWaddr 00:16:3e:76:35:d1' in interfaces[0])
        self.assertTrue('inet addr:192.168.0.232 ' in interfaces[0])
        self.assertTrue('Bcast:192.168.0.255 ' in interfaces[0])
        self.assertTrue('Mask:255.255.255.0' in interfaces[0])

        self.assertTrue(interfaces[1].startswith('lo '))
        self.assertTrue('inet addr:127.0.0.1 ' in interfaces[1])
        self.assertTrue('Mask:255.0.0.0' in interfaces[1])

        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ifconfig_bad_input_multiple_params(self):
        """ Tests if 'ifconfig asd up' works """

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
        cd_command = 'ifconfig asd lol'
        channel.send(cd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, cd_command)
        self.assertEquals(command_output, 'SIOCSIFFLAGS: Operation not permitted')
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ifconfig_bad_input(self):
        """ Tests if 'ifconfig asd' works """

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
        cd_command = 'ifconfig asd'
        channel.send(cd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, cd_command)
        self.assertEquals(command_output, 'asd: error fetching interface information: Device not found')
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ifconfig_interface_param(self):
        """ Tests if 'ifconfig eth0' works """

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
        cd_command = 'ifconfig eth0'
        channel.send(cd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, cd_command)
        self.assertTrue(command_output.startswith('eth0 '))
        self.assertTrue('HWaddr 00:16:3e:76:35:d1' in command_output)
        self.assertTrue('inet addr:192.168.0.232 ' in command_output)
        self.assertTrue('Bcast:192.168.0.255 ' in command_output)
        self.assertTrue('Mask:255.255.255.0' in command_output)
        self.assertFalse('lo  ' in command_output)
        self.assertFalse('127.0.0.1' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ifconfig_loopback_param(self):
        """ Tests if 'ifconfig lo' works """

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
        cd_command = 'ifconfig lo'
        channel.send(cd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, cd_command)
        self.assertTrue(command_output.startswith('lo  '))
        self.assertFalse('HWaddr 00:16:3e:76:35:d1' in command_output)
        self.assertFalse('inet addr:192.168.0.232 ' in command_output)
        self.assertTrue('lo  ' in command_output)
        self.assertTrue('127.0.0.1' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ifconfig_version_param(self):
        """ Tests if 'ifconfig --version' works """

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

        # Now send the ifconfig command
        ifconfig_command = 'ifconfig --version'
        channel.send(ifconfig_command + '\r\n')

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
                                         'commands', 'ifconfig', 'version')
        with open(version_file_path) as version_file:
            for line in version_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, ifconfig_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ifconfig_help_param(self):
        """ Tests if 'ifconfig --help' works """

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

        # Now send the ifconfig command
        ifconfig_command = 'ifconfig --help'
        channel.send(ifconfig_command + '\r\n')

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
        help_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                      'commands', 'ifconfig', 'help')
        with open(help_file_path) as help_file:
            for line in help_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, ifconfig_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()


if __name__ == '__main__':
    unittest.main()
