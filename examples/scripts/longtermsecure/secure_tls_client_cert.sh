#!/bin/sh
#
# This is an example of a script to run a "secure" TURN DTLS client
# with the long-term credentials mechanism and with certificate check.
#
# Options:
#
# 1) -t means that TCP networking is used.
# 2) -S means "SSL protocol with default encryption"
# 3) -i sets certificate file for TLS. -R sets certificate check mode.
#    -E sets CA file for certificate check.
# 4) -k sets private key file for TLS.
# 5) -n 1000 means 1000 messages per single emulated client. Messages
# are sent with interval of 20 milliseconds, to emulate an RTP stream.
# 6) -m 10 means that 10 clients are emulated.
# 7) -l 170 means that the payload size of the packets is 170 bytes 
# (like average audio RTP packet).
# 8) -e 127.0.0.1 means that the clients will use peer IPv4 address 127.0.0.1.
# 9) -g means "set DONT_FRAGMENT parameter in TURN requests".
# 10) -u bolt means that if the server challenges the client with 
# authentication challenge, then we use account "bolt".
# 11) -w kwyjibo sets the password for the account.
# 12) -s option means that the client will be using "send" mechanism for data.
# 13) 127.0.0.1 (the last parameter) is the TURN Server IP address. 
# We use IPv6 - to - IPv4 here to illustrate how the TURN Server 
# converts the traffic from IPv6 to IPv4 and back.
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -t -S -i turn_server_cert.pem -k turn_server_pkey.pem -E turn_server_cert.pem -n 1000 -m 10 -l 170 -e 127.0.0.1 -X -g -u bolt -w kwyjibo -s $@ 127.0.0.1

