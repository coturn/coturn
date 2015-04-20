#!/bin/sh
#
# This is an example how to start a TURN Server in
# secure mode with SQLite database for users
# with the long-term credentials mechanism.
#
# We start here a TURN Server listening on IPv4 address
# 127.0.0.1 and on IPv6 address ::1. We use 127.0.0.1 as
# IPv4 relay address, and we use ::1 as IPv6 relay address.
#
# Other options:
#
# 1) set bandwidth limit on client session 3000000 bytes per second (--max-bps).
# 2) use fingerprints (-f)
# 3) use 3 relay threads (-m 3)
# 4) use min UDP relay port 32355 and max UDP relay port 65535
# 5) "-r north.gov" means "use authentication realm north.gov"
# 6) --db=<file-name> 
# means that local database <file-name> will be used.
# 7) "--cert=example_turn_server_cert.pem" sets the OpenSSL certificate file name. 
# 8) "--pkey=example_turn_server_pkey.pem" sets the OpenSSL private key name.
# 9) "--log-file=stdout" means that all log output will go to the stdout.
# 10) --cipher-list=ALL means that we support all OpenSSL ciphers
# 11) --oauth - support oAuth security dialog
# Other parameters (config file name, etc) are default.

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/

PATH="./bin/:../bin/:../../bin/:${PATH}" turnserver --server-name="blackdow.carleon.gov" -v --syslog -a -L 127.0.0.1 -L ::1 -E 127.0.0.1 -E ::1 --max-bps=3000000 -f -m 3 --min-port=32355 --max-port=65535 -r north.gov --db="var/db/turndb" --cert=turn_server_cert.pem --pkey=turn_server_pkey.pem --log-file=stdout --cipher-list=ALL --oauth $@ 

