#!/bin.sh
nohup mcf &
sleep 10
service tomcat6 restart
