#!/bin/sh
#
# This is an example of a MASTER TURN server that distributes
# the load among several "slave" TURN servers.
#
# The TURN Server is started in
# secure mode (when authentication is used) - see option -a
# that means "use long-term credential mechanism".
#
# We start here a TURN Server listening on IPv4 address
# 127.0.0.1. We use 127.0.0.1 as the relay address, too.
#
# Other options:
#
# 1) set bandwidth limit on client session 3000000 bytes per second (--max-bps).
# 2) use fingerprints (-f)
# 3) use 3 relay threads (-m 3)
# 4) use min UDP relay port 32355 and max UDP relay port 65535
# 5) "-r north.gov" means "use authentication realm north.gov"
# 6) "--user=ninefingers:0xbc807ee29df3c9ffa736523fb2c4e8ee" means 
# "allow user 'ninefinger' with generated key '0xbc807ee29df3c9ffa736523fb2c4e8ee' ".
# 7) "--user=gorst:hero" means "allow user 'gorst' with password 'hero' ". 
# 8) "--log-file=stdout" means that all log output will go to the stdout. 
# 9) "-v" means normal verbose mode (with some moderate logging).
# 10) --no-dtls and --no-tls measn that we are not using DTLS & TLS protocols here 
# (for the sake of simplicity).
# 11) --alternate-server options set the "slave" servers.
# Other parameters (config file name, etc) are default.

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/:/usr/local/mysql/lib/

PATH="./bin/:../bin/:../../bin/:${PATH}" turnserver --syslog -a -L 127.0.0.1 -E 127.0.0.1 --max-bps=3000000 -f -m 3 --min-port=32355 --max-port=65535 --user=ninefingers:0xbc807ee29df3c9ffa736523fb2c4e8ee --user=gorst:hero -r north.gov --log-file=stdout -v --no-dtls --no-tls --alternate-server=127.0.0.1:3333 --alternate-server=127.0.0.1:4444 $@
 
