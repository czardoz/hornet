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
from telnetsrv.green import TelnetHandler

logger = logging.getLogger(__name__)


class Shell(TelnetHandler):
    """
        This class implements the shell functionality. It handles the various VirtualHosts and
        functions as the point of communication for a Session.
    """
    PROMPT = ''
    WELCOME = ''

    def __init__(self, request, client_address, server, session, vhosts, config):
        self.session = session
        self.vhosts = vhosts
        self.login_stack = []
        self.logging = logger
        self.current_host = None
        self.config = config
        TelnetHandler.__init__(self, request, client_address, server)

    def set_host(self, host):
        self.login_stack.append(host)
        self.current_host = host
        self.current_host.login(self.username, self)
        self.PROMPT = self.current_host.prompt
        self.WELCOME = self.current_host.welcome

    def handle(self):  # pragma: no cover

        if not self.authentication_ok():
            return

        default_host = self.vhosts[self.config.default_hostname]
        self.set_host(default_host)
        self.session_start()
        while self.RUNSHELL:
            raw_input_ = self.readline(prompt=self.PROMPT).strip()
            self.input = self.input_reader(self, raw_input_)
            self.raw_input = self.input.raw
            if self.input.cmd:
                cmd = self.input.cmd
                params = self.input.params
                try:
                    command = getattr(self.current_host, 'run_' + cmd)
                    command(params, self)
                except:
                    self.writeerror("{}: command not found".format(cmd))
        self.logging.debug("Exiting handler")
