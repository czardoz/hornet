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
import os

from tarfile import filemode  # Coverts file/directory mode into the ls format (e.g drwxr-xr-x)
import time
from fs.errors import BackReferenceError

logger = logging.getLogger(__name__)


class _PathInfo(object):

    def __init__(self, path, total, output, path_exists, is_dir):
        self.path = path
        self.total = total / 2
        self.path_output = output
        self.path_exists = path_exists
        self.is_dir = is_dir


class LsCommand(object):
    def __init__(self, args, paths, filesystem, working_path):
        self.args = args
        self.paths = sorted(paths)
        self.filesystem = filesystem
        self.working_path = working_path
        self.output = {}

    def process(self):
        for count, p in enumerate(self.paths):
            try:
                self._process_path(p)
            except BackReferenceError as e:
                logger.warn('Access to the external file system was attempted.')
                new_path = os.path.join(self.working_path, p.strip('../'))
                self._process_path(new_path, key_path=p)
        result = ''
        if len(self.paths) == 1:
            path = self.paths[0]
            current_path_info = self.output[path]
            if self.args.l:
                if not self.args.directory:
                    if current_path_info.is_dir:
                        result += 'total {}\n'.format(current_path_info.total)
                result += '\n'.join(current_path_info.path_output)
            else:
                result += ' '.join(current_path_info.path_output)
        else:
            for path in self.paths:
                current_path_info = self.output[path]
                if current_path_info.is_dir:
                    if not self.args.directory:
                        result += '{}:\n'.format(path)
                if self.args.l:
                    if not self.args.directory and current_path_info.is_dir:
                        result += 'total {}\n'.format(current_path_info.total)
                    result += '\n'.join(current_path_info.path_output)
                else:
                    result += ' '.join(current_path_info.path_output)
                if not self.args.directory:
                    result += '\n\n'
                else:
                    result += '\n'
        return result.strip()  # remove the last newline, because shell.writeline() will introduce it later.

    def _stat_path(self, path):
        stat_result = os.stat(self.filesystem.getsyspath(path))
        try:
            last_modified = time.strftime("%b %d %H:%M", time.localtime(stat_result.st_mtime))
        except ValueError:
            last_modified = time.strftime("%b %d %H:%M")
        name = os.path.basename(path) or '.'
        total = stat_result.st_blocks
        if self.args.l:
            path_string = "%s %2s %s %s %6s %s %s" % (
                filemode(stat_result.st_mode),
                stat_result.st_nlink,
                'ftp',
                'ftp',
                stat_result.st_size,
                last_modified,
                name
            )
        else:
            path_string = name
        return {'path_string': path_string, 'total': total}

    def _process_path(self, path, key_path=None):
        path_output = []
        is_directory = False
        if self.args.directory:
            if self.filesystem.isfile(path) or self.filesystem.isdir(path):
                exists = True
                stat = self._stat_path(path)
                path_output.append(stat['path_string'])
                total = stat['total']
                if self.filesystem.isdir(path):
                    is_directory = True
            else:
                exists = False
                total = 0
                path_output.append('ls: cannot access {}: No such file or directory'.format(path))
            path_info = _PathInfo(path, total, path_output, exists, is_directory)
            self._add_path_output(path_info, key_path)
        else:
            if self.filesystem.isdir(path):
                # Process all files one by one, adding to the output list
                exists = True
                total = 0
                is_directory = True
                for file_ in self.filesystem.listdir(path):
                    file_path = os.path.join(path, file_)
                    stat = self._stat_path(file_path)
                    path_output.append(stat['path_string'])
                    total += stat['total']
            elif self.filesystem.isfile(path):
                exists = True
                stat = self._stat_path(path)
                path_output.append(stat['path_string'])
                total = stat['total']
            else:
                exists = False
                total = 0
                path_output.append('ls: cannot access {}: No such file or directory'.format(path))
        path_info = _PathInfo(path, total, path_output, exists, is_directory)
        self._add_path_output(path_info, key_path)

    def _add_path_output(self, path_info, key_path):
        if key_path is None:
            self.output[path_info.path] = path_info
        else:
            self.output[key_path] = path_info
