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
import gevent.monkey

gevent.monkey.patch_all()

import random
import string
import unittest
import tempfile
import os

from hornet.core.fs_wrapper import SandboxedFS


class HornetTests(unittest.TestCase):

    def test_create(self):
        """ Test basic 'ls' """

        testfs = self.create_filesystem()
        new_filename = self.random_name()

        res = testfs.create(new_filename)

        self.assertTrue(res)

        # ensure file exists on disk
        self.assertTrue(os.path.isfile(os.path.join(testfs.root_path, new_filename)))

    def test_makedir(self):
        testfs = self.create_filesystem()
        new_dirname = self.random_name()

        res = testfs.makedir(new_dirname)

        self.assertIsNotNone(res)

        # ensure directory exists on disk
        self.assertTrue(os.path.isdir(os.path.join(testfs.root_path, new_dirname)))

    def create_filesystem(self):
        temp_dir = tempfile.mkdtemp(prefix='test_hornet_')
        return SandboxedFS(temp_dir)

    def random_name(self):
        return ''.join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(6)
        )
