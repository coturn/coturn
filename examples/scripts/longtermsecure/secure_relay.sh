#!/bin/sh
#
# This is an example how to start a TURN Server in
# secure mode (when authentication is used) - see option -a
# that means "use long-term credential mechanism".
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
# 5) "-r north.gov" means "use authentication realm north.gov"
# 6) "--user=ninefingers:youhavetoberealistic" means 
# "allow user 'ninefinger' with password 'youhavetoberealistic' ".
# 7) "--user=gorst:hero" means "allow user 'gorst' with password 'hero' ".
# 8) "--cert=turn_server_cert.pem" sets the OpenSSL certificate file name. 
# 9) "--pkey=turn_server_pkey.pem" sets the OpenSSL private key name.
# 10) "--log-file=stdout" means that all log output will go to the stdout. 
# 11) "-v" means normal verbose mode (with some moderate logging).
# 12) --cipher-list=ALL means that we support all OpenSSL ciphers
# 13) --cli-password=secret means that cli password set to "secret"
# Other parameters (config file name, etc) are default.

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/

PATH="./bin/:../bin/:../../bin/:${PATH}" turnserver --syslog -a -L 127.0.0.1 -L ::1 -E 127.0.0.1 -E ::1 --allow-loopback-peers --max-bps=3000000 -f -m 10 --min-port=32355 --max-port=65535 --user=ninefingers:youhavetoberealistic --user=gorst:hero -r north.gov --cert=turn_server_cert.pem --pkey=turn_server_pkey.pem --log-file=stdout -v --cipher-list=ALL --cli-password=secret --db=var/db/turndb $@
