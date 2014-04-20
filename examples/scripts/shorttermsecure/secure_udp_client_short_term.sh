#!/bin/sh
#
# This is an example of a script to run a "secure" TURN UDP client
# with short-term credential mechanism.
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
# 10) -A means that the short-term credentials mechanism is used.
# 11) -u ninefingers sets the client user name.
# 12) -w youhavetoberealistic sets the password for the user account as "youhavetoberealistic".
# 13) -s option means that the client will be using "send" indication for data trasfer.
# 14) ::1 (the last parameter) is the TURN Server IP address. We use IPv6 here
# to illustrate how the TURN Server convert the traffic from IPv6 to IPv4 and back.
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -n 1000 -m 10 -l 170 -e 127.0.0.1 -X -g -A -u ninefingers -w youhavetoberealistic -s $@ ::1
