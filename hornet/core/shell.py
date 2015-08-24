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

import argparse
import curses

import logging
import socket
import arrow

from telnetsrv.green import TelnetHandler

logger = logging.getLogger(__name__)


class Shell(TelnetHandler):
    """
        This class implements the shell functionality. It handles the various VirtualHosts and
        functions as the point of communication for a Session.
    """
    PROMPT = ''
    WELCOME = ''

    def __init__(self, request, client_address, server, session, vhosts, config, db_handler):
        self.session = session
        self.vhosts = vhosts
        self.login_stack = []
        self.logging = logger
        self.current_host = None
        self.config = config
        self.raw_input = None
        self.input = None
        self.command_greenlet = None
        self.interrupt = False
        self.db_handler = db_handler
        self.db_handler.create_attack_session(self.session)

        TelnetHandler.__init__(self, request, client_address, server)

    def set_host(self, host, default=False):

        self.current_host = host
        if default:
            self.current_host.login(self.username)
            self.writeline(self.current_host.welcome)
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
            try:
                raw_input_ = self.readline(prompt=self.PROMPT).strip()
                self.input = self.input_reader(self, raw_input_)
                self.raw_input = self.input.raw
                if self.input.cmd:

                    # Clear the interrupt flag
                    self.interrupt = False

                    cmd = self.input.cmd
                    params = self.input.params
                    try:
                        if cmd == 'QUIT':  # Handle Ctrl+D
                            cmd = 'logout'
                        if cmd in {'ssh', 'logout'}:  # These are handled by the Shell itself.
                            command = getattr(self, 'run_' + cmd)
                            command(params)
                        else:  # The rest of the commands are handled by the VirtualHosts
                            command = getattr(self.current_host, 'run_' + cmd)
                            command(params, self)
                    except AttributeError:
                        # User entered something we have not implemented.
                        logger.exception('AttributeError occured while running '
                                         'command "%s" with params "%s"', cmd, params)
                        self.writeerror("{}: command not found".format(cmd))
                    except:
                        logger.exception('Unknown exception has occured')
                        self.writeerror("{}: command not found".format(cmd))
                    finally:
                        self.PROMPT = self.current_host.prompt
                        self.db_handler.create_attack_command(
                            self.session.id, cmd, self.current_host
                        )
            except socket.error:
                break
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
        if hostname not in self.vhosts:
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
        current_host = self.login_stack.pop()
        current_host.logout()
        prev_host = self.login_stack[-1]
        self.set_host(prev_host)

    def setterm(self, term):
        """ Set the curses structures for this terminal """
        logger.debug("Setting termtype to %s" % (term, ))
        try:
            curses.setupterm(term)  # This will raise if the termtype is not supported
        except TypeError:
            file_ = open('/dev/null', 'w')
            dummyfd = file_.fileno()
            curses.setupterm(term, fd=dummyfd)

        self.TERM = term
        self.ESCSEQ = {}
        for k in self.KEYS.keys():
            str_ = curses.tigetstr(curses.has_key._capability_names[k])
            if str_:
                self.ESCSEQ[str_] = k
        # Create a copy to prevent altering the class
        self.CODES = self.CODES.copy()
        self.CODES['DEOL'] = curses.tigetstr('el')
        self.CODES['DEL'] = curses.tigetstr('dch1')
        self.CODES['INS'] = curses.tigetstr('ich1')
        self.CODES['CSRLEFT'] = curses.tigetstr('cub1')
        self.CODES['CSRRIGHT'] = curses.tigetstr('cuf1')

    def inputcooker_store_queue(self, char):  # pragma: no cover
        """Put the cooked data in the input queue (no locking needed)"""
        if type(char) in [type(()), type([]), type("")]:
            for v in char:
                if v == chr(3):
                    self.interrupt = True
                self.cookedq.put(v)
        else:
            if char == chr(3):
                self.interrupt = True
            self.cookedq.put(char)

    def updateline(self, data):
        self.write('\r')
        self.write(self.CODES['DEOL'])
        self.write(data)

    def writecooked(self, text):
        TelnetHandler.writecooked(self, text)
        self.session.last_activity = arrow.now().timestamp
