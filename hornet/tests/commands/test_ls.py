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
import re
import os
import unittest

import hornet

from hornet.main import Hornet
from hornet.tests.commands.base import BaseTestClass

LS_L_REGEX = r"[-d][rwx-]{9}(.*)"


class HornetTests(BaseTestClass):

    def test_basic_ls(self):
        """ Test basic 'ls' """

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

        # Now send the ls command
        ls_command = 'ls'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue('etc' in command_output)
        self.assertTrue('var' in command_output)
        self.assertTrue('bin' in command_output)
        self.assertTrue('initrd.img' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_version_string(self):
        """ Test basic 'ls --version' """

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

        # Now send the ls command
        ls_command = 'ls --version'
        channel.send(ls_command + '\r\n')

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
                                         'commands', 'ls', 'version')
        with open(version_file_path) as version_file:
            for line in version_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, ls_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))
        honeypot.stop()

    def test_ls_help_string(self):
        """ Test basic 'ls --help' """

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

        # Now send the ls command
        ls_command = 'ls --help'
        channel.send(ls_command + '\r\n')

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
                                      'commands', 'ls', 'help')
        with open(help_file_path) as help_file:
            for line in help_file:
                line = line.strip()
                expected_output.append(line)

        self.assertEquals(command, ls_command)
        self.assertEquals(command_output, '\r\n'.join(expected_output))
        self.assertTrue(next_prompt.endswith('$ '))
        honeypot.stop()

    def test_ls_long(self):
        """ Test basic 'ls -l' """

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

        # Now send the ls command
        ls_command = 'ls -l'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        actual_list = command_output.split('\r\n')[1:]  # Ignore the first "total" entry
        expected_list = ['initrd.img', 'var', 'etc', 'bin']
        self.verify_long_list(actual_list, expected_list)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_dir_args(self):
        """ Test basic 'ls etc var' """

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

        # Now send the ls command
        ls_command = 'ls etc var'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        dir_outputs = sorted(command_output.split('\r\n\r\n'))

        self.assertTrue('etc:\r\n' in dir_outputs[0])
        self.assertTrue('passwd' in dir_outputs[0])
        self.assertTrue('init.d' in dir_outputs[0])
        self.assertTrue('sysctl.conf' in dir_outputs[0])

        self.assertTrue("var:" in dir_outputs[1])
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_long_dir_args(self):
        """ Test basic 'ls -l etc var' with multiple directory arguments """

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

        # Now send the ls command
        ls_command = 'ls -l etc var'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        dir_outputs = sorted(command_output.split('\r\n\r\n'))

        self.assertTrue(dir_outputs[0].startswith('etc:'))
        self.assertTrue('total ' in dir_outputs[0])
        self.assertTrue('passwd' in dir_outputs[0])
        self.assertTrue('sysctl.conf' in dir_outputs[0])  # No carriage return here, because it was split before
        self.assertTrue('init.d' in dir_outputs[0])  # No carriage return here, because it was split before
        self.assertEquals(len(dir_outputs[0].split('\r\n')), 5)

        self.assertTrue(dir_outputs[1].startswith('var:'))
        self.assertTrue('total 0' in dir_outputs[1])
        self.assertTrue(len(dir_outputs[1].split('\r\n')) == 2)

        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_long_file_args(self):
        """ Test basic 'ls -l etc/passwd etc/sysctl.conf' with multiple file arguments """

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

        # Now send the ls command
        ls_command = 'ls -l etc/passwd etc/sysctl.conf'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        actual_list = command_output.split('\r\n')
        expected_list = ['passwd', 'sysctl.conf']
        self.verify_long_list(actual_list, expected_list)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_d_with_dir_argument(self):
        """ Test basic 'ls -d bin' with single directory argument """

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

        # Now send the ls command
        ls_command = 'ls -d bin'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertEquals(command_output, 'bin')
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_d_with_multiple_dir_argument(self):
        """ Test basic 'ls -d bin var' with multiple directory arguments """

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

        # Now send the ls command
        ls_command = 'ls -d bin var'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue('bin' in command_output)
        self.assertTrue('var' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_d_non_existant_path(self):
        """ Test basic 'ls -d nonexistantpath' with non-existant path argument """

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

        # Now send the ls command
        ls_command = 'ls -d nonexistantpath'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertEquals(command_output, 'ls: cannot access nonexistantpath: No such file or directory')
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_l_non_existant_path(self):
        """ Test basic 'ls -l nonexistantpath' with non-existant path argument """

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

        # Now send the ls command
        ls_command = 'ls -l nonexistantpath'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertEquals(command_output, 'ls: cannot access nonexistantpath: No such file or directory')
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_ld(self):
        """ Test basic 'ls -ld var bin etc/passwd initrd.img' with files as well as directories """

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

        # Now send the ls command
        ls_command = 'ls -ld var bin etc/passwd initrd.img'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        actual_list = command_output.split('\r\n')
        expected_list = ['initrd.img', 'var', 'passwd', 'bin']
        self.verify_long_list(actual_list, expected_list)
        self.assertTrue('total' not in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_with_backref_directory_argument(self):
        """ Test basic 'ls etc/..' """

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

        # Now send the ls command
        ls_command = 'ls etc/..'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue('etc' in command_output)
        self.assertTrue('var' in command_output)
        self.assertTrue('bin' in command_output)
        self.assertTrue('initrd.img' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_long_backref(self):
        """ Test basic 'ls -l .. var' with multiple directory arguments """

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

        # Now send the ls command
        ls_command = 'ls -l .. var'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        dir_outputs = sorted(command_output.split('\r\n\r\n'))

        self.assertTrue(dir_outputs[0].startswith('..:'))
        self.assertTrue('total ' in dir_outputs[0])
        self.assertTrue('var' in dir_outputs[0])
        self.assertTrue('bin' in dir_outputs[0])
        self.assertTrue('initrd.img' in dir_outputs[0])
        self.assertTrue('etc' in dir_outputs[0])
        self.assertEquals(len(dir_outputs[0].split('\r\n')), 6)

        self.assertTrue(dir_outputs[1].startswith('var:'))
        self.assertTrue('total 0' in dir_outputs[1])
        self.assertEquals(len(dir_outputs[1].split('\r\n')), 2)

        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_backref_overflow(self):
        """ Test basic 'ls ../../..' """

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

        # Now send the ls command
        ls_command = 'ls'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue('etc' in command_output)
        self.assertTrue('var' in command_output)
        self.assertTrue('bin' in command_output)
        self.assertTrue('initrd.img' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_all(self):
        """ Test basic 'ls -a' """

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

        # Now send the ls command
        ls_command = 'ls -a'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue('etc' in command_output)
        self.assertTrue('var' in command_output)
        self.assertTrue('bin' in command_output)
        self.assertTrue('initrd.img' in command_output)
        self.assertTrue('. ' in command_output)
        self.assertTrue('..' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_long_after_cd(self):
        """ Test basic 'cd var; ls -al ../etc' """

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

        cd_command = 'cd var'
        channel.send(cd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        next_prompt = lines[-1]

        self.assertEquals(command, cd_command)
        self.assertTrue(next_prompt.endswith('$ '))

        # Now send the ls command
        ls_command = 'ls -la ../etc'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        actual_list = command_output.split('\r\n')[1:]  # Ignore the first "total" entry
        expected_list = ['init.d', 'passwd', 'sysctl.conf', '..', '.']

        self.assertEquals(command, ls_command)
        self.verify_long_list(actual_list, expected_list)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_long_dir_with_backref(self):
        """ Test basic 'cd var; ls -ld ../etc' """

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

        cd_command = 'cd var'
        channel.send(cd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        next_prompt = lines[-1]

        self.assertEquals(command, cd_command)
        self.assertTrue(next_prompt.endswith('$ '))

        # Now send the ls command
        ls_command = 'ls -ld ../etc'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue(command_output.endswith('etc'))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_all_long_with_multiple_args(self):
        """ Test basic 'ls -la etc initrd.img' """

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

        # Now send the ls command
        ls_command = 'ls -la etc initrd.img'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        dir_outputs = sorted(command_output.split('\r\n\r\n'))

        self.assertEquals(command, ls_command)
        actual_list = dir_outputs[1].split('\r\n')[1:]  # Ignore the first "total" entry
        expected_list = ['.config', 'init.d', 'passwd', 'sysctl.conf', '..', '.']

        self.assertTrue(dir_outputs[0].endswith('initrd.img'))
        self.verify_long_list(actual_list, expected_list)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_all_long_dir(self):
        """ Test basic 'ls -lda' """

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

        # Now send the ls command
        ls_command = 'ls -lda'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue(command_output.endswith('.'))
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_all_with_multiple_dir_args(self):
        """ Test basic 'ls -a etc var' """

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

        # Now send the ls command
        ls_command = 'ls -a etc var'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        dir_outputs = sorted(command_output.split('\r\n\r\n'))

        self.assertEquals(command, ls_command)
        self.assertTrue('passwd' in dir_outputs[0])
        self.assertTrue('.config' in dir_outputs[0])
        self.assertTrue('. ' in dir_outputs[0])
        self.assertTrue('..' in dir_outputs[0])
        self.assertTrue('init.d' in dir_outputs[0])
        self.assertTrue('sysctl.conf' in dir_outputs[0])

        self.assertTrue("var:" in dir_outputs[1])

        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_all_dir(self):
        """ Test basic 'ls -a etc' """

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

        # Now send the ls command
        ls_command = 'ls -ad etc'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]
        self.assertEquals(command, ls_command)
        self.assertTrue('etc' in command_output)
        self.assertFalse('var' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_all_hidden_arg(self):
        """ Test basic 'ls -a .hidden' """

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

        # Now send the ls command
        ls_command = 'ls -a .hidden'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue('. ' in command_output)
        self.assertTrue('..' in command_output)
        self.assertTrue('.rcconf' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_all_dir_hidden_arg(self):
        """ Test basic 'ls -da .hidden' """

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

        # Now send the ls command
        ls_command = 'ls -ad .hidden'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue('.hidden' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_all_file_hidden_arg(self):
        """ Test basic 'ls -a .hidden/.rcconf' """

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

        # Now send the ls command
        ls_command = 'ls -a .hidden/.rcconf'
        channel.send(ls_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, ls_command)
        self.assertTrue('.rcconf' in command_output)
        self.assertFalse('. ' in command_output)
        self.assertFalse('..' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def verify_long_list(self, actual_list, expected_list):
        for exp in expected_list:
            found = False
            regex = LS_L_REGEX + r'{}'.format(exp)
            for act in actual_list:
                if re.match(regex, act):
                    found = True
                    break
            self.assertTrue(found)


if __name__ == '__main__':
    unittest.main()
