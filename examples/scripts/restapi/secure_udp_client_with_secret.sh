#!/bin/sh
#
# This is an example of a script to run a "secure" TURN UDP client
# with the long-term credentials mechanism and with
# secret-based authorization (see TURNServerRESTAPI.pdf document).
#
# Options:
#
# 1) -t is absent, it means that UDP networking is used.
# 5) -n 1000 means 1000 messages per single emulated client. Messages
# are sent with interval of 20 milliseconds, to emulate an RTP stream.
# 6) -m 10 means that 10 clients are emulated.
# 7) -l 170 means that the payload size of the packets is 170 bytes 
# (like average audio RTP packet).
# 8) -e 127.0.0.1 means that the clients will use peer address 127.0.0.1.
# 9) -g means "set DONT_FRAGMENT parameter in TURN requests".
# 10) -u ninefingers means that if the server challenges the client with 
# authentication challenge, then we use account "ninefingers".
# 11) -W logen  sets the secret for the secret-based authentication as "logen".
# 12) -s option is absent - it means that the client will be using 
# the "channel" mechanism for data.
# 13) ::1 (the last parameter) is the TURN Server IPv6 address. 
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -z 5 -n 10000 -s -m 10 -l 170 -e 127.0.0.1 -X -g -u ninefingers -W logen $@ ::1
