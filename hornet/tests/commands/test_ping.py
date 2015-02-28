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

gevent.monkey.patch_all()

import paramiko
import os
import hornet

from hornet.main import Hornet
from hornet.tests.commands.base import BaseTestClass


class HornetTests(BaseTestClass):

    def test_ping_help(self):
        """ Tests basic 'ping -h' """

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the ping command
        ping_command = 'ping -h'
        channel.send(ping_command + '\r\n')

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
                                      'commands', 'ping', 'help')
        with open(help_file_path) as help_file:
            for line in help_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, ping_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ping_unknown_host(self):
        """ Tests basic 'ping lolwakaka' """

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the ping command
        ping_command = 'ping lolwakaka'
        channel.send(ping_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ping_command)
        self.assertEquals(command_output, 'ping: unknown host lolwakaka')
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ping_multiple_hosts(self):
        """ Tests basic 'ping lolwakaka awasd'
            Makes sure the last param is picked up as the host to ping.
        """

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the ping command
        ping_command = 'ping lolwakaka awasd'
        channel.send(ping_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ping_command)
        self.assertEquals(command_output, 'ping: unknown host awasd')
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ping_ctrl_c(self):
        """ Tests basic 'ping test01'
            Makes sure the last param is picked up as the host to ping.
        """

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the ping command
        ping_command = 'ping test01'
        channel.send(ping_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        lines = []
        for i in range(2):
            line = ''
            while not line.endswith('\r\n'):
                line += channel.recv(1)
            lines.append(line.strip('\r\n'))
        channel.send(chr(3))

        output = ''
        while not output.endswith('$ '):
            data = channel.recv(1)
            output += data

        lines = output.split('\r\n')
        lines = [l for l in lines if not l.startswith('64 bytes from')]  # Skip the ping response lines

        self.assertEquals('^C', lines[0])
        self.assertEquals('--- test01 ping statistics ---', lines[1])

        self.assertTrue('packets transmitted, ' in lines[2])
        self.assertTrue('received, ' in lines[2])
        self.assertTrue('% packet loss, time' in lines[2])
        self.assertTrue(lines[2].endswith('ms'))

        self.assertTrue(lines[3].startswith('rtt min/avg/max/mdev = '))
        self.assertTrue(lines[3].endswith('ms'))

        next_prompt = lines[-1]
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ping_ctrl_c_ip_addr(self):
        """ Tests basic 'ping 192.168.0.232'
            Makes sure the last param is picked up as the host to ping.
        """

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
        self.assertTrue(prompt.endswith('$ '))

        # Now send the ping command
        ping_command = 'ping 192.168.0.232'
        channel.send(ping_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        lines = []
        for i in range(2):
            line = ''
            while not line.endswith('\r\n'):
                line += channel.recv(1)
            line = line.strip('\r\n')
            if line.startswith('64 bytes from'):
                self.assertTrue('test02 (192.168.0.232)' in line)
            lines.append(line)
        channel.send(chr(3))

        output = ''
        while not output.endswith('$ '):
            data = channel.recv(1)
            output += data

        lines = output.split('\r\n')
        lines = [l for l in lines if not l.startswith('64 bytes from')]  # Skip the ping response lines

        self.assertEquals('^C', lines[0])
        self.assertEquals('--- 192.168.0.232 ping statistics ---', lines[1])

        self.assertTrue('packets transmitted, ' in lines[2])
        self.assertTrue('received, ' in lines[2])
        self.assertTrue('% packet loss, time' in lines[2])
        self.assertTrue(lines[2].endswith('ms'))

        self.assertTrue(lines[3].startswith('rtt min/avg/max/mdev = '))
        self.assertTrue(lines[3].endswith('ms'))

        next_prompt = lines[-1]
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()