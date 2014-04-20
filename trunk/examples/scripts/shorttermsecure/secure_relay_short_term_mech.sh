#!/bin/sh
#
# This is an example how to start a TURN Server in
# secure mode with short-term security mechanism - see option -A
# that means "use short-term credential mechanism".
#
# The short-term credentials mechanism must be used with PostgreSQL or 
# MySQL database only, the flat file userdb cannot be used.
#
# We listen on available interfaces here, and we use the "external" IPs
# for relay endpoints allocation.
#
# Other options:
#
# 1) set bandwidth limit on client session 3000000 bytes per second (--max-bps).
# 2) use fingerprints (-f)
# 3) use 3 relay threads (-m 3)
# 4) use min UDP relay port 32355 and max UDP relay port 65535
# 5) --mysql-userdb="host=localhost dbname=coturn user=turn password=turn connect_timeout=30" 
# means that local MySQL database "coturn" will be used, with database user "turn" and 
# database user password "turn", and connection timeout 30 seconds.
# 6) "--cert=example_turn_server_cert.pem" sets the OpenSSL certificate file name. 
# 7) "--pkey=example_turn_server_pkey.pem" sets the OpenSSL private key name.
# 8) "--log-file=stdout" means that all log output will go to the stdout.
# 9) -E 127.0.0.1 and -E :;1 sets the relay addresses, in this case for loopback 
# communications only.
# 10) --cipher-list=ALL:SSLv2 means that we support all OpenSSL ciphers, including SSLv2.
# Other parameters (config file name, etc) are default.

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/

PATH="./bin/:../bin/:../../bin/:${PATH}" turnserver -v --syslog -A --max-bps=3000000 -f -m 3 --min-port=32355 --max-port=65535  --mysql-userdb="host=localhost dbname=coturn user=turn password=turn connect_timeout=30" --cert=turn_server_cert.pem --pkey=turn_server_pkey.pem --log-file=stdout -E 127.0.0.1 -E ::1 --cipher-list=ALL:SSLv2 $@
