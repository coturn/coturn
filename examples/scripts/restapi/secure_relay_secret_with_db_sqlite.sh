#!/bin/sh
#
# This is an example how to start a TURN Server in
# secure 'dynamic' 'secret' mode (see TURNServerRESTAPI.pdf)
# with SQLite database for users information
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
# 5) --use-auth-secret means that we are using 'secret' authentication mode.
# Absense of --static-auth-secret value means that we will be taking the secret value
# from the database ('dynamic' mode).
# 6) --realm=north.gov sets realm value as "north.gov".
# 7) --db=<file-name> 
# means that local SQLite database <file-name> will be used.
# 8) "--cert=example_turn_server_cert.pem" sets the OpenSSL certificate file name. 
# 9) "--pkey=example_turn_server_pkey.pem" sets the OpenSSL private key name.
# 10) "--log-file=stdout" means that all log output will go to the stdout.
# 11) --cipher-list=ALL means that we support all OpenSSL ciphers
# Other parameters (config file name, etc) are default.

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/

PATH="./bin/:../bin/:../../bin/:${PATH}" turnserver -v --syslog -a -L 127.0.0.1 -L ::1 -E 127.0.0.1 -E ::1 --max-bps=3000000 -f -m 3 --min-port=32355 --max-port=65535 --use-auth-secret --realm=north.gov --db="var/db/turndb" --cert=turn_server_cert.pem --pkey=turn_server_pkey.pem --log-file=stdout --cipher-list=ALL $@
