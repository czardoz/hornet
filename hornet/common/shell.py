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

from telnetsrv.green import TelnetHandler, command

logger = logging.getLogger(__name__)


class Shell(TelnetHandler):
    """This class implements the shell functionality for the telnet and SSH capabilities"""

    def __init__(self, request, client_address, session):
        self.session = session
        TelnetHandler.__init__(self, request, client_address, None)

    @command('echo')
    def command_echo(self, params):
        self.writeline(' '.join(params))
