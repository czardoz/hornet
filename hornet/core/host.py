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

import argparse
import logging
import os
import gevent
import hornet

from fs.errors import BackReferenceError
from fs.osfs import OSFS
from hornet.common.helpers import get_random_item
from hornet.core.commands.ifconfig_command import IfconfigCommand
from hornet.core.commands.ls_command import LsCommand
from hornet.core.commands.ping_command import PingCommand
from hornet.core.commands.wget_command import WgetCommand

logger = logging.getLogger(__name__)


class Parser(argparse.ArgumentParser):

    def error(self, message):
        logger.info('User supplied wrong arguments: {}'.format(message))
        raise ParseError()


class ParseError(Exception):
    pass


class VirtualHost(object):

    """ Represents a single host. This class implements the commands
        that are host-specific, like pwd, ls, etc.
    """

    def __init__(self, params, network, fs_dir):
        self.hostname = params['hostname']
        self.ip_address = params['ip_address']
        self.network = network
        self.env = params['env']

        valid_ips = map(str, network[1:-1])
        if self.ip_address is None:
            logger.error('IP address for {} is not specified in the config file (or is "null")'.format(self.hostname))
            if not self._set_ip_from_previous_run(fs_dir, valid_ips):
                self.ip_address = get_random_item(valid_ips)
                logger.info('Assigned random IP {} to host {}'.format(self.ip_address, self.hostname))
        else:
            if not self.ip_address in valid_ips:
                logger.error('IP Address {} for {} is not valid for the specified network'.format(
                    params['ip_address'], self.hostname))
                if not self._set_ip_from_previous_run(fs_dir, valid_ips):
                    self.ip_address = get_random_item(valid_ips)
                    logger.info('Assigned random IP {} to host {}'.format(self.ip_address, self.hostname))

        self.valid_logins = params['valid_logins']
        self.logged_in = False
        self.current_user = None
        if params.get('default', False):
            self.default = True
        else:
            self.default = False
        self.filesystem = OSFS(os.path.join(fs_dir, '{}_{}'.format(self.hostname, self.ip_address)), create=True)
        self.working_path = '/'

    def authenticate(self, username, password):
        if self.valid_logins.get(username, None) == password:
            return True
        return False

    def login(self, username):
        logger.debug('User "{}" has logged into "{}" host'.format(username, self.hostname))
        self.logged_in = True
        self.current_user = username

    def logout(self):
        self.logged_in = False
        self.current_user = None

    @property
    def welcome(self):
        if self.filesystem.isfile('/etc/motd'):
            with self.filesystem.open('/etc/motd') as motd_file:
                return motd_file.read()
        else:
            return 'Welcome to {} server.'.format(self.hostname)

    @property
    def prompt(self):
        prompt = '{}@{}:{}$ '.format(self.current_user, self.hostname, self.working_path)
        return prompt

    def run_echo(self, params, shell):
        if not params:
            shell.writeline('')
        elif params[0].startswith('$') and len(params) == 1:
            var_name = params[0][1:]
            value = self.env.get(var_name, '')
            shell.writeline(value)
        elif '*' in params:
            params.remove('*')
            params.extend(self.filesystem.listdir())
            shell.writeline(' '.join(params))
        else:
            shell.writeline(' '.join(params))

    def run_pwd(self, params, shell):
        if params:
            shell.writeline('pwd: too many arguments')
        else:
            shell.writeline('{}'.format(self.working_path))

    def run_wget(self, params, shell):
        parser = Parser(add_help=False)
        parser.add_argument('-h', '--help', action='store_true', default=False)
        parser.add_argument('-V', '--version', action='store_true', default=False)
        parser.add_argument('-O', '--output-document')
        args, unparsed = parser.parse_known_args(params)

        if unparsed:
            url = unparsed[0]
        elif not args.help and not args.version:
            shell.writeline('wget: missing URL')
            shell.writeline('Usage: wget [OPTION]... [URL]...')
            shell.writeline('')
            shell.writeline('Try \'wget --help\' for more options.')
            return

        if args.help:
            help_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                          'commands', 'wget', 'help')
            self.send_data_from_file(help_file_path, shell)
            return

        if args.version:
            version_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                             'commands', 'wget', 'version')
            self.send_data_from_file(version_file_path, shell)
            return

        wget_command = WgetCommand(url, self.working_path, self.filesystem, args, shell)
        wget_command.process()

    def run_ping(self, params, shell):

        options = [x for x in params if x.startswith('-')]

        if '-h' in options or len(params) == 0:
            help_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                          'commands', 'ping', 'help')
            self.send_data_from_file(help_file_path, shell)
            return

        filtered_params = [p for p in params if not p.startswith('-')]

        ping_host = filtered_params[-1]
        logger.debug('Going to ping {}'.format(ping_host))
        ping_command = PingCommand(ping_host, shell)
        ping_command.process()

    def run_ifconfig(self, params, shell):
        if len(params) >= 2:
            shell.writeline('SIOCSIFFLAGS: Operation not permitted')
            return
        if params:
            parameter = params[0]
            if parameter == '--version':
                version_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                                 'commands', 'ifconfig', 'version')
                self.send_data_from_file(version_file_path, shell)
                logger.debug('Sending version string for ifconfig from {} file'.format(version_file_path))
                return
            elif parameter == '--help' or parameter == '-h':
                help_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                              'commands', 'ifconfig', 'help')
                self.send_data_from_file(help_file_path, shell)
                logger.debug('Sending version string for ifconfig from {} file'.format(help_file_path))
                return
        output_template_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                            'commands', 'ifconfig', 'output_template')
        ifconfig_command = IfconfigCommand(params, output_template_path, self.ip_address, self.network)
        output = ifconfig_command.process()
        shell.writeline(output)

    def run_ls(self, params, shell):
        paths = []
        other_params = []
        for p in params:
            if p.startswith('-'):
                other_params.append(p)
            else:
                paths.append(p)

        if not paths:  # List contents of working dir by default
            paths.append(self.working_path)

        parser = Parser(add_help=False)
        parser.add_argument('-a', '--all', action='store_true', default=False)
        parser.add_argument('-A', '--almost-all', action='store_true', default=False)
        parser.add_argument('-d', '--directory', action='store_true', default=False)
        parser.add_argument('-l', action='store_true', default=False)

        # We ignore these (for now), but still parse them ;-)
        parser.add_argument('-h', '--human-readable', action='store_true', default=False)
        parser.add_argument('-b', '--escape', action='store_true', default=False)
        parser.add_argument('--block-size')
        parser.add_argument('-B', '--ignore-backups', action='store_true', default=False)
        parser.add_argument('-c', action='store_true', default=False)
        parser.add_argument('-C', action='store_true', default=False)
        parser.add_argument('--color')
        parser.add_argument('-D', '--dired', action='store_true', default=False)
        parser.add_argument('-f', action='store_true', default=False)
        parser.add_argument('-F', '--classify', action='store_true', default=False)
        parser.add_argument('--file-type', action='store_true', default=False)
        parser.add_argument('--format')
        parser.add_argument('--full-time', action='store_true', default=False)
        parser.add_argument('-g', action='store_true', default=False)
        parser.add_argument('--group-directories-first', action='store_true', default=False)
        parser.add_argument('-G', '--no-group', action='store_true', default=False)
        parser.add_argument('-H', '--dereference-command-line', action='store_true', default=False)
        parser.add_argument('--dereference-command-line-symlink-to-dir', action='store_true', default=False)
        parser.add_argument('--hide')
        parser.add_argument('--indicator-style')
        parser.add_argument('-i', '--inode', action='store_true', default=False)
        parser.add_argument('-I', '--ignore')
        parser.add_argument('-k', '--kibibytes', action='store_true', default=False)
        parser.add_argument('-L', '--deference', action='store_true', default=False)
        parser.add_argument('-m', action='store_true', default=False)
        parser.add_argument('-n', '--numeric-uid-gid', action='store_true', default=False)
        parser.add_argument('-N', '--literal', action='store_true', default=False)
        parser.add_argument('-o', action='store_true', default=False)
        parser.add_argument('-p', action='store_true', default=False)
        parser.add_argument('-q', '--hide-control-chars', action='store_true', default=False)
        parser.add_argument('--show-control-chars', action='store_true', default=False)
        parser.add_argument('-Q', '--quote-name', action='store_true', default=False)
        parser.add_argument('--quoting-style')
        parser.add_argument('-r', '--reverse', action='store_true', default=False)
        parser.add_argument('-R', '--recursive', action='store_true', default=False)
        parser.add_argument('-s', '--size', action='store_true', default=False)
        parser.add_argument('-S', action='store_true', default=False)
        parser.add_argument('--sort')
        parser.add_argument('--time')
        parser.add_argument('--time-style')
        parser.add_argument('-t', action='store_true', default=False)
        parser.add_argument('-T', '--tabsize', default=False)
        parser.add_argument('-u', action='store_true', default=False)
        parser.add_argument('-U', action='store_true', default=False)
        parser.add_argument('-v', action='store_true', default=False)
        parser.add_argument('-w', '--width')
        parser.add_argument('-x', action='store_true', default=False)
        parser.add_argument('-X', action='store_true', default=False)
        parser.add_argument('-1', dest='one_per_line', action='store_true', default=False)
        parser.add_argument('--help', action='store_true', default=False)
        parser.add_argument('--version', action='store_true', default=False)

        try:
            args = parser.parse_args(other_params)
        except ParseError:
            shell.writeline('ls: invalid options: \"{}\"'.format(' '.join(params)))
            shell.writeline('Try \'ls --help\' for more information.')
            return

        if args.help:
            help_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                          'commands', 'ls', 'help')
            logger.debug('Sending help string from file {}'.format(help_file_path))
            self.send_data_from_file(help_file_path, shell)
            return

        if args.version:
            version_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                             'commands', 'ls', 'version')
            logger.debug('Sending version string from file {}'.format(version_file_path))
            self.send_data_from_file(version_file_path, shell)
            return

        ls_cmd = LsCommand(args, paths, self.filesystem, self.working_path)
        output = ls_cmd.process()
        shell.writeline(output)

    def run_cd(self, params, shell):
        if len(params) == 0:
            params = ['/']
        cd_path = os.path.join(self.working_path, params[0])
        new_path_exists = False
        try:
            new_path_exists = self.filesystem.exists(cd_path)
        except BackReferenceError as e:
            logger.warn('Access to the external file system was attempted.')
            cd_path = '/'
            new_path_exists = True
        finally:
            if not new_path_exists:
                shell.writeline('cd: {}: No such file or directory'.format(params[0]))
            else:
                self.working_path = os.path.normpath(cd_path)
                logger.debug('Working directory for host {} changed to {}'.format(self.hostname, self.working_path))

    def run_uname(self, params, shell):

        if not params:
            shell.writeline('Linux')
            return

        buff = ''
        info = ['Linux', self.hostname, '3.13.0-37-generic',
                '#64-Ubuntu SMP Mon Sep 22 21:30:01 UTC 2014', 'i686',
                'i686', 'i686', 'GNU/Linux']
        parser = Parser(add_help=False)
        parser.add_argument('-a', '--all', default=False, action='store_true')
        parser.add_argument('-s', '--kernel-name', default=False, action='store_true')
        parser.add_argument('-n', '--nodename', default=False, action='store_true')
        parser.add_argument('-r', '--kernel-release', default=False, action='store_true')
        parser.add_argument('-v', '--kernel-version', default=False, action='store_true')
        parser.add_argument('-m', '--kernel-machine', default=False, action='store_true')
        parser.add_argument('-p', '--processor', default=False, action='store_true')
        parser.add_argument('-i', '--hardware-platform', default=False, action='store_true')
        parser.add_argument('-o', '--operating-system', default=False, action='store_true')
        parser.add_argument('--help', default=False, action='store_true')
        parser.add_argument('--version', default=False, action='store_true')

        try:
            args = parser.parse_args(params)
        except ParseError:
            shell.writeline('uname: invalid options -- \'{}\''.format(' '.join(params)))
            shell.writeline('Try \'uname --help\' for more information.')
            return

        if args.all:
            buff = ' '.join(info)
            shell.writeline(buff)
            return
        if args.help:
            help_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                          'commands', 'uname', 'help')
            self.send_data_from_file(help_file_path, shell)
            return
        if args.version:
            version_file_path = os.path.join(os.path.dirname(hornet.__file__), 'data',
                                             'commands', 'uname', 'version')
            self.send_data_from_file(version_file_path, shell)
            return
        if args.kernel_name:
            buff = buff + info[0] + ' '
        if args.nodename:
            buff = buff + self.hostname + ' '
        if args.kernel_release:
            buff = buff + info[2] + ' '
        if args.kernel_version:
            buff = buff + info[3] + ' '
        if args.kernel_machine:
            buff = buff + info[4] + ' '
        if args.processor:
            buff = buff + info[4] + ' '
        if args.hardware_platform:
            buff = buff + info[4] + ' '
        if args.operating_system:
            buff += 'GNU/Linux'

        shell.writeline(buff)

    def _set_ip_from_previous_run(self, fs_dir, valid_ips):  # pragma: no cover
        for dir_name in os.listdir(fs_dir):
            if dir_name.startswith(self.hostname + '_'):
                possible_ip = dir_name.split('_')[1]
                if possible_ip in valid_ips:
                    self.ip_address = possible_ip
                    logger.info('Assigned IP {} to host {}'.format(self.ip_address, self.hostname))
                    return True
        return False

    @staticmethod
    def send_data_from_file(path, shell):
        with open(path, 'r') as infile:
            for line in infile:
                line = line.strip()
                shell.writeline(line)
