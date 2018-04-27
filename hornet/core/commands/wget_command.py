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

import logging
import os
import random
import urlparse
import gevent
import requests
import requests.exceptions
import time
import socket

from contextlib import closing
from hornet.common.helpers import human_readable

logger = logging.getLogger(__name__)


class WgetCommand(object):

    PROGRESS_BAR = '{:.0%}[{}>{}] {:,}  {}'

    def __init__(self, url, working_path, filesystem, args, shell):
        self.shell = shell
        self.url = url
        self.parsed_url = None
        self.args = args
        self.working_path = working_path
        self.filesystem = filesystem
        self.outputfile = None
        self.fail_flag = False
        self.session = requests.session()

        self.ip_address = None
        self.port = None
        self.content_type = None

        # Used to render the progressbar
        self.progressbar_size = 50

        # Used to calculate download progress and speed
        self.total_size = 0
        self.currently_downloaded = 0
        self.start_time = None

        if self.args.output_document:
            self.outputfile = self.args.output_document
        else:
            self.outputfile = url.split('/')[-1]
            if not self.outputfile:
                self.outputfile = 'index.html'

    def process(self):
        self._parse_url()
        self._get_total_size()

        if self.fail_flag:
            self._write_info_line()
            self._write_dns_resolution_failed()
            self.shell.writeline('wget: unable to resolve host address \'{}\''.format(self.parsed_url.hostname))
            return

        self._write_info_line()
        self._write_dns_resolution_successful()
        self._write_connection_info()

        output_path = os.path.join(self.working_path, self.outputfile)
        with open(self.filesystem.getsyspath(output_path), 'w') as output:
            self.start_time = time.clock()
            with closing(self.session.get(self.url, stream=True)) as response:
                progress_greenlet = gevent.spawn(self._render_progressbar)
                logger.debug('Progress greenlet started')
                for data in response.iter_content(128):
                    if data:
                        self.currently_downloaded += len(data)
                        output.write(data)
                        gevent.sleep(0)
                logger.debug('Download complete')
                gevent.joinall([progress_greenlet])
                self._write_conclusion()

    def _get_total_size(self):
        try:
            resp = self.session.get(self.url)
        except requests.exceptions.RequestException:
            self.fail_flag = True
            return
        if not resp.status_code == 200:
            logger.debug('Response for url: {} is "{}"'.format(self.url, resp.status_code))
            self.fail_flag = True
            return
        content_length = resp.headers.get('content-length', None)
        if content_length:
            try:
                self.total_size = int(content_length)
            except ValueError:
                logger.error('Invalid content-length received '
                             'for url ({}): {}'.format(self.url, content_length))
                self.fail_flag = True
        elif len(resp.content):
            self.total_size = len(resp.content)
        else:
            self.fail_flag = True
        self.content_type = resp.headers.get('content-type', None)
        if not self.content_type:
            self.content_type = 'text/plain'
        logger.debug('Total size set to: {}'.format(self.total_size))

    def _write_info_line(self):
        self.shell.writeline('--{}-- {}'.format(time.strftime('%Y-%m-%d %H:%M:%S'), self.url))

    def _write_dns_resolution_failed(self):
        self.shell.writeline('Resolving {} ({})... failed: Name or service '
                             'not known.'.format(self.parsed_url.hostname, self.parsed_url.hostname))

    def _write_dns_resolution_successful(self):
        try:
            # This will generally be successful. If the hostname was really not
            # resolved, `_get_total_size()` would have failed.
            self.ip_address = socket.gethostbyname(self.parsed_url.hostname)
        except socket.error:
            self.ip_address = '.'.join(''.format(random.randint(1, 254)) for i in range(4))
        self.shell.writeline('Resolving {0} ({0})... {1}'.format(
            self.parsed_url.hostname,
            self.ip_address,
        ))

    def _write_connection_info(self):
        self.shell.writeline('Connecting to {0} ({0})|{1}|:{2}... connected.'.format(
            self.parsed_url.hostname,
            self.ip_address,
            self.port
        ))
        self.shell.writeline('HTTP request sent, awaiting response... 200 OK')
        self.shell.writeline('Length: {} ({}) [{}]'.format(
            self.total_size,
            human_readable(self.total_size),
            self.content_type
        ))
        self.shell.writeline('Saving to:\'{}\''.format(self.outputfile))
        self.shell.writeline('')

    def _render_progressbar(self):
        while not self.currently_downloaded == self.total_size:
            self.shell.updateline(self._get_progressbar())
            gevent.sleep(0.3)
        # Update one last time to show 100% progress
        self.shell.updateline('{}  in {:.2f}s'.format(self._get_progressbar(), time.clock()-self.start_time))
        self.shell.writeline('')

    def _get_progressbar(self):
        percent = self.currently_downloaded / float(self.total_size)
        done = int(percent * self.progressbar_size)
        not_done = self.progressbar_size - done

        elapsed_time = time.clock() - self.start_time
        speed = human_readable(self.currently_downloaded / elapsed_time, suffix='B/s')
        return self.PROGRESS_BAR.format(
            percent,
            (done - 1) * '=',
            not_done * ' ',
            self.total_size,
            speed
        )

    def _parse_url(self):
        self.parsed_url = urlparse.urlparse(self.url)
        if not self.parsed_url.scheme.startswith('http'):
            self.fail_flag = True
            return
        self.port = self.parsed_url.port
        if not self.port:
            if self.parsed_url.scheme == 'http':
                self.port = 80
            else:
                self.port = 443

    def _write_conclusion(self):
        self.shell.writeline('{} - \'{}\' saved [{}/{}]'.format(
            time.strftime('%Y-%m-%d %H:%M:%S'),
            self.outputfile,
            self.currently_downloaded,
            self.total_size
        ))
