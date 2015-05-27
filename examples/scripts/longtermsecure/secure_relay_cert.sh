#!/bin/sh
#
# This is an example how to start a TURN Server in
# secure mode (when authentication is used) - see option -a
# that means "use long-term credential mechanism".
#
# This script shows how to use certificate check option.
#
# We start here a TURN Server listening on IPv4 address
# 127.0.0.1 and on IPv6 address ::1. We use 127.0.0.1 as
# IPv4 relay address, and we use ::1 as IPv6 relay address.
#
# Other options:
#
# 1) set bandwidth limit on client session 3000000 bytes per second (--max-bps).
# 2) use fingerprints (-f)
# 3) use 10 relay threads (-m 10)
# 4) use min UDP relay port 32355 and max UDP relay port 65535
# 5) "-r bolt.co" means "use authentication realm 'bolt.co'"
# 6) "--user=ninefingers:youhavetoberealistic" means "allow user 
#			'ninefinger' with password 'youhavetoberealistic'.".
# 7) "--user=bolt:kwyjibo" means "allow user 'bolt' with password 'kwyjibo' ".
# 8) "--cert=..." sets the OpenSSL certificate file name. 
# 9) "--pkey=..." sets the OpenSSL private key name.
# 10) --CA-file sets the CA file for client certificate check.
# 11) "--log-file=stdout" means that all log output will go to the stdout.
# 12) "-v" means normal verbose mode (with some moderate logging).
# 13) --cipher-list="ALL:!eNULL:!aNULL:!NULL" measn "all ciphers, except anonymous".
# Other parameters (config file name, etc) are default.

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/

PATH="./bin/:../bin/:../../bin/:${PATH}" turnserver --syslog -a -L 127.0.0.1 -L ::1 -E 127.0.0.1 -E ::1 --max-bps=3000000 -f -m 10 --min-port=32355 --max-port=65535 --user=ninefingers:youhavetoberealistic --user=bolt:kwyjibo -r bolt.co --cert=turn_server_cert.pem --pkey=turn_server_pkey.pem --CA-file=turn_server_cert.pem --log-file=stdout -v --cipher-list="ALL:!eNULL:!aNULL:!NULL" --db=var/db/turndb $@
