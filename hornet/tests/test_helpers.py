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

import os
import shutil
import unittest
import tempfile

import hornet
from hornet.common.helpers import get_random_item


class HornetTests(unittest.TestCase):

    def setUp(self):
        self.working_dir = tempfile.mkdtemp()
        test_config = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
        shutil.copyfile(test_config, os.path.join(self.working_dir, 'config.json'))

    def tearDown(self):
        shutil.rmtree(self.working_dir)

    def test_random_choice_dict(self):
        test_dict = {
            'a': 1,
            'b': 2,
            'c': 3,
            'd': 4
        }
        x = get_random_item(test_dict)
        self.assertTrue(x in test_dict.values())

    def test_random_choice_list(self):
        test_list = range(4, 99)
        x = get_random_item(test_list)
        self.assertTrue(4 <= x <= 99)
