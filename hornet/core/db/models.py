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

from sqlalchemy import Column, String, DateTime, UnicodeText, ForeignKey, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class AttackSession(Base):

    __tablename__ = 'attacksession'

    id = Column(String(50), primary_key=True)
    start_time = Column(DateTime)
    source_ip = Column(String(16))
    source_port = Column(Integer)
    end_time = Column(DateTime)
    commands = relationship('AttackCommand', backref='session', order_by='AttackCommand.time',
                            cascade="all, delete-orphan")

class AttackCommand(Base):

    __tablename__ = 'attackcommand'

    id = Column(Integer, autoincrement=True, primary_key=True)
    time = Column(DateTime)
    command = Column(String(2048))
    host = Column(String(2048))
    output = Column(UnicodeText)
    session_id = Column(String(50), ForeignKey('attacksession.id'))
