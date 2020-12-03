#!/bin/sh
docker run --detach --name=actw_mysql --env="MYSQL_ROOT_PASSWORD=password" --publish 3306:3306 mysql:5.7
# --volume=/root/docker/[container_name]/conf.d:/etc/mysql/conf.d \

