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

import re
import random
import gevent
import logging

IP_ADDRESS_REGEX = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." \
                    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." \
                    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." \
                    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$"

logger = logging.getLogger(__name__)


class PingCommand(object):

    def __init__(self, host, shell):
        self.host = host
        self.shell = shell
        self.ip = None

        # These record the stats to show at the end
        self.total_count = 1
        self.success_count = 0
        self.times = []

        # These are used to randomize pings
        self.mean = random.randint(13, 140)
        self.standard_deviation = 3
        self.success_probability = 0.93

    def process(self):

        self._resolve_hostname()
        if not self.ip:
            self.shell.writeline('ping: unknown host {}'.format(self.host))
            return

        self.shell.writeline('PING {} ({}) 56(84) bytes of data.'.format(self.host, self.ip))

        while not self.shell.interrupt:
            if random.uniform(0, 1) < self.success_probability:
                time = random.normalvariate(self.mean, self.standard_deviation)
                line = '64 bytes from {} ({}): icmp_seq={} ttl=53 time={:.1f} ms'.format(
                    self.host,
                    self.ip,
                    self.total_count,
                    time
                )
                self.success_count += 1
                self.times.append(time)
                self.shell.writeline(line)
            self.total_count += 1
            gevent.sleep(1)

        self.shell.writeline('^C')
        self.shell.writeline('--- {} ping statistics ---'.format(self.host))
        self.shell.writeline('{} packets transmitted, {} received, {} packet loss, time {}ms'.format(
            self.total_count, self.success_count, self._get_percentage_packet_loss(), sum(self.times)
        ))
        self.shell.writeline('rtt min/avg/max/mdev = {:.2f}/{:.2f}/{:.2f}/{:.2f} ms'.format(
            min(self.times),
            sum(self.times) / self.total_count,
            max(self.times),
            self._get_std_deviation()
        ))

    def _resolve_hostname(self):
        if re.match(IP_ADDRESS_REGEX, self.host):
            self.ip = self.host  # Able to ping any IP
            logger.debug('Set IP to {}'.format(self.ip))
        else:
            if self.host in self.shell.vhosts:  # Only ping hosts in our honeypot
                self.ip = self.shell.vhosts[self.host].ip_address

    def _get_percentage_packet_loss(self):
        return '{:.2%}'.format(1 - float(self.success_count)/self.total_count)

    def _get_std_deviation(self):
        variance = sum((t - self.mean)**2 for t in self.times)
        return (variance / self.total_count) ** 0.5
