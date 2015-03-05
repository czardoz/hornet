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
import urlparse
import requests
import requests.exceptions
import time

logger = logging.getLogger(__name__)


class WgetCommand(object):

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

        # Used to calculate download progress
        self.total_size = 0
        self.currently_downloaded = 0

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
            self.shell.writeline('Resolving {} ({})... failed: Name or service '
                                 'not known.'.format(self.parsed_url.hostname, self.parsed_url.hostname))
            self.shell.writeline('wget: unable to resolve host address \'{}\''.format(self.parsed_url.hostname))
            return

    def _get_total_size(self):
        try:
            resp = self.session.head(self.url)
        except requests.exceptions.RequestException:
            self.fail_flag = True
            return
        if not resp.status_code == 200:
            logger.debug('Response for url: {} is "{}"'.format(self.url, resp.status_code))
            self.fail_flag = True
            return
        content_length = resp.headers.get('content-length', None)
        if not content_length:
            self.fail_flag = True
        else:
            try:
                self.total_size = int(content_length)
            except ValueError:
                logger.error('Invalid content-length received '
                             'for url ({}): {}'.format(self.url, content_length))
                self.fail_flag = True
        logger.debug('Total size set to: {}'.format(self.total_size))

    def _write_info_line(self):
        self.shell.writeline('--{}-- {}'.format(time.strftime('%Y-%m-%d %H:%M:%S'), self.url))

    def _parse_url(self):
        self.parsed_url = urlparse.urlparse(self.url)
        if not self.parsed_url.scheme.startswith('http'):
            self.fail_flag = True