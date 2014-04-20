#!/bin/sh
#
# This is a script for the peer application,
# for testing only purposes. It opens UDP echo-like sockets
# on IPv4 address 127.0.0.1 and IPv6 address ::1.
# The default port 3480 is used.
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/

PATH=examples/bin/:bin/:../bin:${PATH} turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 $@
