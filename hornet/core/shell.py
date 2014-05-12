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
import curses

import logging
import traceback

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

    def set_host(self, host, default=False):

        self.current_host = host
        if default:
            self.current_host.login(self.username)
        self.PROMPT = self.current_host.prompt
        self.WELCOME = self.current_host.welcome

    def handle(self):  # pragma: no cover

        if not self.authentication_ok():
            return

        default_host = self.vhosts[self.config.default_hostname]
        self.login_stack.append(default_host)
        self.set_host(default_host, default=True)
        self.session_start()
        while self.RUNSHELL:
            raw_input_ = self.readline(prompt=self.PROMPT).strip()
            self.input = self.input_reader(self, raw_input_)
            self.raw_input = self.input.raw
            if self.input.cmd:
                cmd = self.input.cmd
                params = self.input.params
                try:
                    if cmd in ['ssh', 'logout']:
                        command = getattr(self, 'run_' + cmd)
                        command(params)
                    else:
                        command = getattr(self.current_host, 'run_' + cmd)
                        command(params, self)
                except AttributeError:
                    # User entered something we have not implemented.
                    self.writeerror("{}: command not found".format(cmd))
                except:
                    logger.error(traceback.print_exc())
                    self.writeerror("{}: command not found".format(cmd))
        self.logging.debug("Exiting handler")

    def run_ssh(self, params):
        parser = argparse.ArgumentParser()
        parser.add_argument('-p', dest='port', default=22, type=int)
        parser.add_argument('-l', dest='username')
        parser.add_argument('host_string')
        args = parser.parse_args(params)
        username = args.username
        if username is None:
            try:
                username, _ = args.host_string.split('@')
            except ValueError:
                username = self.current_host.current_user
        if '@' in args.host_string:
            _, hostname = args.host_string.split('@')
        else:
            hostname = args.host_string
        if not hostname in self.vhosts:
            self.writeline('ssh: Could not resolve hostname {}: Name or service not known'.format(hostname))
            return

        # Hostname is valid. Now get the password.
        new_host = self.vhosts[hostname]
        password = self.readline(echo=False, prompt=self.PROMPT_PASS, use_history=False)
        if new_host.authenticate(username, password):
            self.login_stack.append(new_host)
            new_host.login(username)
            self.set_host(new_host)
            self.writeline(new_host.welcome)

    def run_logout(self, _):  # Don't care about the params
        if len(self.login_stack) == 1:
            self.RUNSHELL = False
            self.login_stack = []
            return
        del self.login_stack[-1]
        prev_host = self.login_stack[-1]
        self.set_host(prev_host)

    def setterm(self, term):
        "Set the curses structures for this terminal"
        logger.debug("Setting termtype to %s" % (term, ))
        try:
            curses.setupterm(term) # This will raise if the termtype is not supported
        except TypeError:
            file_ = open('/dev/null', 'w')
            dummyfd = file_.fileno()
            curses.setupterm(term, fd=dummyfd)

        self.TERM = term
        self.ESCSEQ = {}
        for k in self.KEYS.keys():
            str = curses.tigetstr(curses.has_key._capability_names[k])
            if str:
                self.ESCSEQ[str] = k
        # Create a copy to prevent altering the class
        self.CODES = self.CODES.copy()
        self.CODES['DEOL'] = curses.tigetstr('el')
        self.CODES['DEL'] = curses.tigetstr('dch1')
        self.CODES['INS'] = curses.tigetstr('ich1')
        self.CODES['CSRLEFT'] = curses.tigetstr('cub1')
        self.CODES['CSRRIGHT'] = curses.tigetstr('cuf1')
