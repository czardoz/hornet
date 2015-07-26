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

import uuid
import arrow
import gevent
import logging

logger = logging.getLogger(__name__)


class Session(object):

    def __init__(self, client_address, session_q):
        self.id = uuid.uuid4()
        self.start_time = arrow.now().timestamp
        self.client_address = client_address
        self.session_q = session_q
        self.last_activity = arrow.now().timestamp
        self.watcher_greenlet = gevent.spawn(self.watch)

    def watch(self, max_diff=60):
        logger.debug('Started watching %s', self)
        while True:
            diff = arrow.now().timestamp - self.last_activity
            if diff > max_diff:
                logger.debug('Detected inactive session: %s', self.id)
                self.session_q.put(self)
                break
            gevent.sleep(5)

    def __repr__(self):
        return '<Session last_activity={}, id={}, client_address={}>'.format(
            self.last_activity,
            self.id,
            self.client_address
        )
