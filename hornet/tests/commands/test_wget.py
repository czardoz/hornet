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
import unittest

import gevent.monkey
import hornet

gevent.monkey.patch_all()

import paramiko
from hornet.main import Hornet
from hornet.tests.commands.base import BaseTestClass


class HornetTests(BaseTestClass):

    def test_wget_bad_hostname(self):
        """ Tests if 'wget http://asdjkhaskdh/index.html' works (bad hostname case) """

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

        # Now send the wget command
        wget_command = 'wget http://asdjkhaskdh/index.html'
        channel.send(wget_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        next_prompt = lines[-1]

        self.assertEquals(command, wget_command)

        self.assertTrue(lines[1].startswith('--'))
        self.assertTrue('http://asdjkhaskdh/index.html' in lines[1])
        self.assertEquals('Resolving asdjkhaskdh (asdjkhaskdh)... '
                          'failed: Name or service not known.', lines[2])
        self.assertEquals('wget: unable to resolve host address \'asdjkhaskdh\'', lines[3])
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_wget_help_param(self):
        """ Tests if 'wget --help' works """

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

        # Now send the wget command
        wget_command = 'wget --help'
        channel.send(wget_command + '\r\n')

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
                                      'commands', 'wget', 'help')
        with open(help_file_path) as help_file:
            for line in help_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, wget_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_wget_version_param(self):
        """ Tests if 'wget --version' works """

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

        # Now send the wget command
        wget_command = 'wget --version'
        channel.send(wget_command + '\r\n')

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
                                         'commands', 'wget', 'version')
        with open(version_file_path) as version_file:
            for line in version_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, wget_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_wget_bad_returncode(self):
        """ Tests if 'wget http://httpbin.org/status/500' shows an error resolving """

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

        # Now send the wget command
        wget_command = 'wget http://httpbin.org/status/500'
        channel.send(wget_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        next_prompt = lines[-1]

        self.assertEquals(command, wget_command)

        self.assertTrue(lines[1].startswith('--'))
        self.assertTrue('http://httpbin.org/status/500' in lines[1])
        self.assertEquals('Resolving httpbin.org (httpbin.org)... '
                          'failed: Name or service not known.', lines[2])
        self.assertEquals('wget: unable to resolve host address \'httpbin.org\'', lines[3])
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_wget_no_content_length(self):
        """ Tests if 'wget http://pathod.net/response_preview?spec=200:r' shows an error resolving """

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

        # Now send the wget command
        wget_command = 'wget http://pathod.net/response_preview?spec=200:r'
        channel.send(wget_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        next_prompt = lines[-1]

        self.assertEquals(command, wget_command)

        self.assertTrue(lines[1].startswith('--'))
        self.assertTrue('http://pathod.net/response_preview?spec=200:r' in lines[1])
        self.assertEquals('Resolving pathod.net (pathod.net)... '
                          'failed: Name or service not known.', lines[2])
        self.assertEquals('wget: unable to resolve host address \'pathod.net\'', lines[3])
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_wget_bad_content_length(self):
        """ Tests if 'wget http://pathod.net/response_preview?spec=200%3Ar%3Ah%22Content-Length
        %22%3D%22%27unparsable%22' shows an error resolving """

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

        # Now send the wget command
        wget_command = 'wget http://pathod.net/response_preview?spec=200%3Ar%3Ah%22' \
                       'Content-Length%22%3D%22%27unparsable%22'
        channel.send(wget_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        next_prompt = lines[-1]

        self.assertEquals(command, wget_command)

        self.assertTrue(lines[1].startswith('--'))
        self.assertTrue('http://pathod.net/response_preview?spec=200%3Ar%3Ah%22'
                        'Content-Length%22%3D%22%27unparsable%22' in lines[1])
        self.assertEquals('Resolving pathod.net (pathod.net)... '
                          'failed: Name or service not known.', lines[2])
        self.assertEquals('wget: unable to resolve host address \'pathod.net\'', lines[3])
        self.assertTrue(next_prompt.endswith('$ '))
        honeypot.stop()


if __name__ == '__main__':
    unittest.main()