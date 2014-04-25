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

import logging
import os
from paramiko import SSHException

from telnetsrv.paramiko_ssh import SSHHandler
from hornet.common.session import Session
from hornet.core.shell import Shell
from hornet.common.helpers import get_rsa_key_file

logger = logging.getLogger(__name__)

AUTH_SUCCESSFUL, AUTH_PARTIALLY_SUCCESSFUL, AUTH_FAILED = range(3)


class SSHWrapper(object):

    """ Helper class to pass the client socket to _SSHHandler """

    def __init__(self, vhosts, sessions, config, working_directory):
        self.vhosts = vhosts
        self.sessions = sessions
        self.config = config
        self.working_directory = working_directory

    def handle_session(self, client_socket, client_address):
        current_session = Session(client_address)
        self.sessions[current_session.id] = current_session
        logger.info('Connection from {}, {}'.format(client_address, client_socket))

        # Set the host_key attribute on our _SSHHandler class
        key_file_path = os.path.join(self.working_directory, self.config.key_file)
        _SSHHandler.host_key = get_rsa_key_file(key_file_path)

        try:
            _SSHHandler(current_session, client_socket, client_address, self.vhosts)
        except SSHException:
            logging.error('SSH Session {} ended unexpectedly'.format(current_session.id))


class _SSHHandler(SSHHandler):

    telnet_handler = Shell

    def __init__(self, session, socket, client_address, vhosts):
        self.session = session
        self.vhosts = vhosts
        request = _SSHHandler.dummy_request()
        request._sock = socket
        super(_SSHHandler, self).__init__(request, client_address, None)

    def authCallbackUsername(self, username):
        raise  # Disable username based logins.

    def authCallback(self, username, password):
        logger.info('Login attempt: {} -- {}'.format(username, password))
        default = None
        for hostname, host in self.vhosts.iteritems():
            if host.default:
                default = host
        if default.login(username, password):
            return True
        else:
            raise Exception('Bad username/password')

    def setup(self):

        self.transport.load_server_moduli()
        self.transport.add_server_key(self.host_key)
        self.transport.start_server(server=self)

        while True:  # pragma: no cover
            channel = self.transport.accept(20)
            if channel is None:
                # check to see if any thread is running
                any_running = False
                for c, thread in self.channels.items():
                    if thread.is_alive():
                        any_running = True
                        break
                if not any_running:
                    break

    def start_pty_request(self, channel, term, modes):  # pragma: no cover
        """ Start a PTY - intended to run it a (green)thread. """
        request = self.dummy_request()
        request._sock = channel
        request.modes = modes
        request.term = term
        request.username = self.username

        # This should block until the user quits the pty
        self.pty_handler(request, self.client_address, self.tcp_server, self.session, self.vhosts)

        # Shutdown the entire session
        self.transport.close()
