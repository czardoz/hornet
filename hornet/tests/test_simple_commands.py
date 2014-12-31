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

import paramiko
import os
import shutil
import unittest
import tempfile

import hornet
from hornet.main import Hornet


class HornetTests(unittest.TestCase):

    def setUp(self):
        self.working_dir = tempfile.mkdtemp()
        test_config = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
        shutil.copyfile(test_config, os.path.join(self.working_dir, 'config.json'))

    def tearDown(self):
        shutil.rmtree(self.working_dir)

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

    def test_ssh_no_username(self):
        """ Tests if ssh command works when no username is provided in host string
            eg: $ ssh test01
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

        # Now send the ssh command
        channel.send('ssh test01\r\n')
        while not channel.recv_ready():
            gevent.sleep(0)  # :-(
        output = ''
        while not output.endswith('Password:'):
            output += channel.recv(1)

        # Now send the password
        channel.send('passtest\r\n')

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)
        self.assertTrue('Welcome to test01 server' in output)
        self.assertTrue(output.endswith('$ '))
        honeypot.stop()

    def test_ssh_with_username(self):
        """ Tests if ssh command works when username is provided in host string
            eg: $ ssh mango@test01
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

        # Now send the ssh command
        channel.send('ssh root@test01\r\n')
        while not channel.recv_ready():
            gevent.sleep(0)  # :-(
        output = ''
        while not output.endswith('Password:'):
            output += channel.recv(1)

        # Now send the password
        channel.send('toor\r\n')

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)
        self.assertTrue('Welcome to test01 server' in output)
        self.assertTrue(output.endswith('$ '))
        honeypot.stop()

    def test_ssh_with_username_param(self):
        """ Tests if ssh command works when username is provided as a parameter
            eg: $ ssh test01 -l mango
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

        # Now send the ssh command
        channel.send('ssh test01 -l root\r\n')
        while not channel.recv_ready():
            gevent.sleep(0)  # :-(
        output = ''
        while not output.endswith('Password:'):
            output += channel.recv(1)

        # Now send the password
        channel.send('toor\r\n')

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)
        self.assertTrue('Welcome to test01 server' in output)
        self.assertTrue(output.endswith('$ '))
        honeypot.stop()

    def test_ssh_bad_hostname(self):
        """ Tests if ssh command returns correct string if host doesn't exist
            eg: $ ssh test01 -l mango
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

        # Now send the ssh command
        channel.send('ssh blahblah\r\n')
        while not channel.recv_ready():
            gevent.sleep(0)  # :-(
        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)
        self.assertTrue('Name or service not known' in output)
        self.assertTrue(output.endswith('$ '))
        honeypot.stop()

    def test_logout(self):
        """ Tests logout command
            eg: $ logout
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

        # Now send the ssh command
        channel.send('ssh test01\r\n')
        while not channel.recv_ready():
            gevent.sleep(0)  # :-(
        output = ''
        while not output.endswith('Password:'):
            output += channel.recv(1)

        # Now send the password
        channel.send('passtest\r\n')

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)
        self.assertTrue('Welcome to test01 server' in output)
        self.assertTrue(output.endswith('$ '))

        # Now send the logout command
        channel.send('logout\r\n')
        while not channel.recv_ready():
            gevent.sleep(0)  # :-(
        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)
        self.assertTrue('testuser@test02' in output)
        self.assertTrue(output.endswith('$ '))

        honeypot.stop()

    def test_logout_close(self):
        """ Tests logout command when only logged in to the default VirtualHost
            eg: $ logout
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

        # Now send the logout command
        channel.send('logout\r\n')

        honeypot.stop()

    def test_echo_params(self):
        """ Tests if echo command works when parameters are specified """

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

        # Now send the echo command
        channel.send('echo this is a test\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]
        self.assertEquals('echo this is a test', command)
        self.assertEquals('this is a test', command_output)
        self.assertTrue(next_prompt.endswith('$ '))
        honeypot.stop()

    def test_echo_no_params(self):
        """ Tests if echo command works when no parameters are specified """

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

        # Now send the echo command
        channel.send('echo\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]
        self.assertEquals('echo', command)
        self.assertEquals('', command_output)
        self.assertTrue(next_prompt.endswith('$ '))
        honeypot.stop()

    def test_echo_env_var(self):
        """ Tests if echo command works when environment variables as specified in the
            config are specified """

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

        # Now send the echo command
        channel.send('echo $BROWSER\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]
        self.assertEquals('echo $BROWSER', command)
        self.assertEquals('firefox', command_output)
        self.assertTrue(next_prompt.endswith('$ '))
        honeypot.stop()

    def test_echo_star(self):
        """ Tests if echo command works when '*' exists in the params """

        honeypot = Hornet(self.working_dir)
        honeypot.start()
        default_host = honeypot.vhosts[honeypot.config.default_hostname]
        default_host.filesystem.makedir('/etc')
        default_host.filesystem.makedir('/var')
        default_host.filesystem.makedir('/opt')

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

        # Now send the echo command
        channel.send('echo *\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]
        self.assertEquals('echo *', command)
        self.assertTrue('var' in command_output)
        self.assertTrue('etc' in command_output)
        self.assertTrue('opt' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))
        honeypot.stop()

    def test_pwd(self):
        """ Tests if pwd command works """

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

        # Now send the pwd command
        pwd_command = 'pwd /something/ any kind of param 123'
        channel.send(pwd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, pwd_command)
        self.assertEquals(command_output, 'pwd: too many arguments')
        self.assertTrue(next_prompt.endswith('$ '))

        pwd_command = 'pwd'
        channel.send(pwd_command + '\r\n')

        while not channel.recv_ready():
            gevent.sleep(0)  # :-(

        output = ''
        while not output.endswith('$ '):
            output += channel.recv(1)

        lines = output.split('\r\n')
        command = lines[0]
        command_output = '\r\n'.join(lines[1:-1])
        next_prompt = lines[-1]

        self.assertEquals(command, pwd_command)
        self.assertEquals(command_output, '/')
        self.assertTrue(next_prompt.endswith('$ '))
        honeypot.stop()