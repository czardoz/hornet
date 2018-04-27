#!/usr/bin/env bash

sed -i 's/127.0.0.1/0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf
/etc/init.d/mysql restart;
mysql -u root -v -e 'CREATE DATABASE IF NOT EXISTS hornet;';
mysql -u root -v -e "CREATE USER 'hornetservice'@'%';";
mysql -u root -v -e "GRANT ALL PRIVILEGES ON *.* TO 'hornetservice'@'localhost';";

mkdir /opt/vfs/;

sed 's/\/\/travis\@/\/\/hornetservice\@/' ./hornet/data/default_config.json > /opt/vfs/config.json;
sed -i 's/port": 0,/port":\ 2222,/' /opt/vfs/config.json;
sed -i 's/"host": "127.0.0.1",/"host": "0.0.0.0",/' /opt/vfs/config.json;

mkdir -p /var/log/supervisord/;
supervisord -n -c ./hornet-supervisord.conf;
