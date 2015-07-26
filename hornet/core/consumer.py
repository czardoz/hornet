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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURzPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import gevent

logger = logging.getLogger(__name__)

class SessionConsumer(object):

    def __init__(self, session_q):
        self.session_q = session_q
        self.run_greenlet = None

    def _process_session(self, session):
        logger.debug('Persisting session %s', session.id)

    def _start_processing(self):
        for session in self.session_q:
            self._process_session(session)

    def start(self):
        self.run_greenlet = gevent.spawn(self._start_processing)
        return self.run_greenlet

    def stop(self):
        logger.info('Consumer stopping, no further sessions will be processed.')
        self.run_greenlet.kill()
