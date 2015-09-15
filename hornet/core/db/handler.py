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
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import AttackCommand, AttackSession, Base

logger = logging.getLogger(__name__)

Session = sessionmaker()


class DatabaseHandler(object):

    def __init__(self, config):
        self.config = config
        logger.debug('Found database configuration: %s', config.database)
        self.engine = create_engine(config.database, echo=False)
        Session.configure(bind=self.engine)
        Base.metadata.create_all(self.engine)

    def create_attack_session(self, session):
        logger.debug('Creating new attack session, %s - start-time: %s remote-addr: %s',
                     session.id, session.start_time, session.client_address)
        with self.session_context() as dbsession:
            attack_session = AttackSession(start_time=session.start_time, id=session.id,
                                           source_ip=session.client_address[0], source_port=session.client_address[1])
            dbsession.add(attack_session)

    def create_attack_command(self, attack_session_id, command, host):
        logger.debug('Adding a new attack command (%s) to session %s.', command, attack_session_id)
        with self.session_context() as dbsession:
            attack_session = dbsession.query(AttackSession).filter_by(id=attack_session_id).one()
            attack_command = AttackCommand(command=command, host=host.hostname, session_id=attack_session.id)
            attack_session.commands.append(attack_command)

    @contextmanager
    def session_context(self):
        session = Session()
        try:
            yield session
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()
