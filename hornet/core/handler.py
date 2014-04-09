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

from telnetsrv.paramiko_ssh import SSHHandler, getRsaKeyFile
from hornet.common.session import Session
from hornet.common.shell import Shell

logger = logging.getLogger(__name__)


class SSHWrapper(object):

    """ Helper class to pass the client socket to _SSHHandler """

    def __init__(self, vhosts, sessions, config):
        self.vhosts = vhosts
        self.sessions = sessions
        self.config = config

    def handle_session(self, client_socket, client_address):
        current_session = Session(client_address)
        self.sessions[current_session.id] = current_session
        logger.info('Connection from {}, {}'.format(client_address, client_socket))

        # Set the host_key attribute on our _SSHHandler class
        key_file_path = os.path.join(os.getcwd(), self.config.key_file)
        _SSHHandler.host_key = getRsaKeyFile(key_file_path)

        try:
            _SSHHandler(current_session, client_socket, client_address)
        except SSHException:
            logging.error('SSH Session {} ended unexpectedly'.format(current_session.id))


class _SSHHandler(SSHHandler):
    """
    Wraps the telnetsrv paramiko module to fit the Honeypot architecture.
    """

    telnet_handler = Shell

    def __init__(self, session, socket, client_address):
        self.session = session
        request = _SSHHandler.dummy_request()
        request._sock = socket
        super(_SSHHandler, self).__init__(request, client_address, None)

    def authCallbackUsername(self, username):
        #make sure no one can logon
        raise

    def authCallback(self, username, password):
        logger.info('Login attempt: {} -- {}'.format(username, password))
        return True

    def setup(self):

        self.transport.load_server_moduli()
        self.transport.add_server_key(self.host_key)
        self.transport.start_server(server=self)

        while True:
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
