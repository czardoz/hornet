FROM ubuntu:16.04

MAINTAINER Aniket Panse <contact@aniketpanse.in>

RUN apt-get clean && \
    apt-get upgrade -y && \
    apt-get update -y --fix-missing && \
    apt-get install -y libmysqlclient-dev python-pip;

ENV MYSQL_DATA_DIR=/var/lib/mysql \
    MYSQL_RUN_DIR=/run/mysqld \
    MYSQL_LOG_DIR=/var/log/mysql;

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server;

RUN mkdir /opt/hornet;
COPY . /opt/hornet
WORKDIR /opt/hornet

RUN pip install . &&\
    which hornet;


ENTRYPOINT ["scripts/run.sh"]
