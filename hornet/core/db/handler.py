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
from sqlalchemy import create_engine

from models import AttackCommand, AttackSession, Base

logger = logging.getLogger(__name__)


class DatabaseHandler(object):

    def __init__(self, config):
        self.config = config
        logger.debug('Found database configuration: %s', config.database)
        self.engine = create_engine(config.database, echo=False)
        Base.metadata.create_all(self.engine)
