#!/usr/bin/bash
port=15044
host=localhost
script=proyxy2json.pl
perl $script > /dev/tcp/$host/$port
exit 0
