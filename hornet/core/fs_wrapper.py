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

import os
import logging

import fs.errors

import hornet

from fs.osfs import OSFS


directories = []

with open(os.path.join(os.path.dirname(hornet.__file__), 'data',
                       'linux_fs_list.txt')) as fslist:
    for line in fslist:
        line = line.strip()
        directories.append(unicode(line))


class SandboxedFS(OSFS):

    def __init__(self, *args, **kwargs):
        create_fs = kwargs.pop('create_fs') if 'create_fs' in kwargs else False
        super(SandboxedFS, self).__init__(*args, **kwargs)
        if create_fs:
            for each in directories:
                try:
                    self.makedirs(each)
                except fs.errors.DirectoryExists as e:
                    logging.debug('Directory creation skipped for: %s', each)

    def isfile(self, path):
        if not isinstance(path, unicode):
            path = unicode(path)
        return super(SandboxedFS, self).isfile(path)

    def open(self,
             path,
             mode="r",
             buffering=-1,
             encoding=None,
             errors=None,
             newline='',
             line_buffering=False,
             **options):
        if not isinstance(path, unicode):
            path = unicode(path)
        logging.debug('Opening a new path: {}, mode={}'.format(path, mode))
        return super(SandboxedFS, self).open(
            path, mode, buffering, encoding, errors, newline, **options
        )

    def exists(self, path):
        if not isinstance(path, unicode):
            path = unicode(path)
        return super(SandboxedFS, self).exists(path)

    def makedir(self, path, permissions=None, recreate=False):
        if not isinstance(path, unicode):
            path = unicode(path)
        return super(SandboxedFS, self).makedir(path, permissions, recreate)

    def create(self, path, wipe=False):
        if not isinstance(path, unicode):
            path = unicode(path)
        return super(SandboxedFS, self).create(path, wipe)

    def listdir(self, path='/'):
        if not isinstance(path, unicode):
            path = unicode(path)
        return super(SandboxedFS, self).listdir(path)

    def isdir(self, path):
        if not isinstance(path, unicode):
            path = unicode(path)
        return super(SandboxedFS, self).isdir(path)
