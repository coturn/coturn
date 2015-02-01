#!/bin/sh
#
# This is an example how to start a TURN Server 
# with self-udp-balancing, in secure mode 
# (when authentication is used) - see option -a
# that means "use long-term credential mechanism".
#
# We start here a TURN Server listening on IPv4 address
# 127.0.0.1 and on IPv6 address ::1. We use 127.0.0.1 as
# IPv4 relay address, and we use ::1 as IPv6 relay address.
#
# Other options:
#
# 1) --aux-server=... options start two auxiliary severs on IP address 127.0.0.1
# and ports 12345 and 12346, and two auxiliary servers on IP adress ::1
# with the same ports.
# 2) --self-udp-balance option forces the server to distribute the load from the 
# main server points to the auxiliary servers through the ALTERNATE-SERVER 
# mechanism.
# 3) set bandwidth limit on client session 3000000 bytes per second (--max-bps).
# 4) use fingerprints (-f)
# 5) use 10 relay threads (-m 10)
# 6) use min UDP relay port 32355 and max UDP relay port 65535
# 7) "-r north.gov" means "use authentication realm north.gov"
# 8) "--user=ninefingers:youhavetoberealistic" means 
# "allow user 'ninefinger' with password 'youhavetoberealistic' ".
# 9) "--user=gorst:hero" means "allow user 'gorst' with password 'hero' ".
# 10) "--cert=example_turn_server_cert.pem" sets the OpenSSL certificate file name. 
# 11) "--pkey=example_turn_server_pkey.pem" sets the OpenSSL private key name.
# 12) "--log-file=stdout" means that all log output will go to the stdout. 
# 13) "-v" means normal verbose mode (with some moderate logging).
# 14) --cipher-list=ALL means that we support all OpenSSL ciphers
# Other parameters (config file name, etc) are default.

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/

PATH="./bin/:../bin/:../../bin/:${PATH}" turnserver --aux-server=127.0.0.1:12345 --aux-server=[::1]:12345 --aux-server=127.0.0.1:12346 --aux-server=[::1]:12346 --udp-self-balance --syslog -a -L 127.0.0.1 -L ::1 -E 127.0.0.1 -E ::1 --max-bps=3000000 -f -m 10 --min-port=32355 --max-port=65535 --user=ninefingers:youhavetoberealistic --user=gorst:hero -r north.gov --cert=turn_server_cert.pem --pkey=turn_server_pkey.pem --log-file=stdout --cipher-list=ALL --db=var/db/turndb $@
