#!/bin/sh
#
# This is an example of a script to run a "secure" TURN TLS client
# with the long-term credentials mechanism.
#
# Options:
#
# 1) -b is present, it means that SCTP networking is used.
# 2) -S means "SSL/TLS protocol with default cipher" will be used over SCTP.
# 3) -i absent.
# 4) -k sets private key file for TLS.
# 5) -n 1000 means 1000 messages per single emulated client. Messages
# are sent with interval of 20 milliseconds, to emulate an RTP stream.
# 6) -m 10 means that 10 clients are emulated.
# 7) -l 170 means that the payload size of the packets is 170 bytes 
# (like average audio RTP packet).
# 8) -e 127.0.0.1 means that the clients will use peer address 127.0.0.1.
# 9) -g means "set DONT_FRAGMENT parameter in TURN requests".
# 10) -u gorst means that if the server challenges the client with 
# authentication challenge, then we use account "gorst".
# 11) -w hero sets the password for the account as "hero".
# 12) -s option means that the client will be using "send" mechanism for data.
# 13) ::1 (the last parameter) is the TURN Server IP address. We use IPv6 here
# to illustrate how the TURN Server convert the traffic from IPv6 to IPv4 and back.
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -b -S -k turn_client_pkey.pem -n 1000 -m 10 -l 170 -e 127.0.0.1 -X -g -u gorst -w hero $@ ::1

