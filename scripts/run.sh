#!/usr/bin/env bash

/etc/init.d/mysql restart;
mysql -u root -v -e 'CREATE DATABASE IF NOT EXISTS hornet;';
mysql -u root -v -e "CREATE USER 'hornetservice'@'localhost';";
mysql -u root -v -e "GRANT ALL PRIVILEGES ON *.* TO 'hornetservice'@'localhost';";

sed 's/\/\/travis\@/\/\/hornetservice\@/' ./hornet/data/default_config.json > config.json
sed -i 's/port": 0,/port":\ 2222,/' config.json
sed -i 's/"host": "127.0.0.1",/"host": "0.0.0.0",/' config.json

mkdir -p /var/log/supervisord/;
mkdir /opt/vfs/;
supervisord -n -c ./hornet-supervisord.conf;
