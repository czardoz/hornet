import gevent.monkey
gevent.monkey.patch_all()

import paramiko
import re
import os
import shutil
import unittest
import tempfile

import hornet
from hornet.main import Hornet

LS_L_REGEX = r"[-d][rwx-]{9}(.*)"


class HornetTests(unittest.TestCase):

    def setUp(self):
        self.working_dir = tempfile.mkdtemp()
        test_config = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
        shutil.copyfile(test_config, os.path.join(self.working_dir, 'config.json'))

    def tearDown(self):
        shutil.rmtree(self.working_dir)

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
        self.assertTrue('crapfile.txt' in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_ls_long(self):
        """ Tests basic 'ls -l' """

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
        expected_list = ['crapfile.txt', 'var', 'etc', 'bin']
        self.verify_long_list(actual_list, expected_list)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_dir_args(self):
        """ Test basic 'ls' with multiple directory arguments """

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
        self.assertTrue("etc:\r\npasswd sysctl.conf" in command_output)
        self.assertTrue("var:" in command_output)
        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_long_dir_args(self):
        """ Test basic 'ls -l' with multiple directory arguments """

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
        self.assertTrue('total 0' in dir_outputs[0])
        self.assertTrue('passwd\r\n' in dir_outputs[0])
        self.assertTrue('sysctl.conf' in dir_outputs[0])  # No carriage return here, because it was split before
        self.assertTrue(len(dir_outputs[0].split('\r\n')) == 4)  # make sure 4 lines are generated

        self.assertTrue(dir_outputs[1].startswith('var:'))
        self.assertTrue('total 0' in dir_outputs[1])
        self.assertTrue(len(dir_outputs[1].split('\r\n')) == 2)

        self.assertTrue(next_prompt.endswith('$ '))

        honeypot.stop()

    def test_basic_ls_long_file_args(self):
        """ Test basic 'ls -l' with multiple file arguments """

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
        """ Test basic 'ls -d' with single directory argument """

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
        """ Test basic 'ls -d' with multiple directory arguments """

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
        """ Test basic 'ls -d' with non-existant path argument """

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
        """ Test basic 'ls -l' with non-existant path argument """

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
        """ Test basic 'ls -ld' with files as well as directories """

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
        ls_command = 'ls -ld var bin etc/passwd crapfile.txt'
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
        expected_list = ['crapfile.txt', 'var', 'passwd', 'bin']
        self.verify_long_list(actual_list, expected_list)
        self.assertTrue('total' not in command_output)
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

    def create_filesystem(self, honeypot):
        default_host = honeypot.vhosts[honeypot.config.default_hostname]
        default_host.filesystem.makedir('/etc')
        default_host.filesystem.makedir('/var')
        default_host.filesystem.makedir('/bin')
        default_host.filesystem.createfile('/etc/passwd')
        default_host.filesystem.createfile('/etc/sysctl.conf')
        default_host.filesystem.createfile('/crapfile.txt')
