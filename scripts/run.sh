#!/usr/bin/env bash

/etc/init.d/mysql restart;
mysql -u root -v -e 'CREATE DATABASE IF NOT EXISTS hornet;';
mysql -u root -v -e "CREATE USER 'travis'@'localhost';";
mysql -u root -v -e "GRANT ALL PRIVILEGES ON *.* TO 'travis'@'localhost';";
hornet -v;
