#!/bin/bash

# Detect cmake build and adjust path
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

echo "Creating $BINDIR/turnserver.conf file"
echo "use-auth-secret" > $BINDIR/turnserver.conf
echo "static-auth-secret=secret" >> $BINDIR/turnserver.conf
echo "realm=north.gov" >> $BINDIR/turnserver.conf
echo "allow-loopback-peers" >> $BINDIR/turnserver.conf
echo "no-cli" >> $BINDIR/turnserver.conf
echo "cert=../examples/ca/turn_server_cert.pem" >> $BINDIR/turnserver.conf
echo "pkey=../examples/ca/turn_server_pkey.pem" >> $BINDIR/turnserver.conf

echo 'Running turnserver'
$BINDIR/turnserver -c $BINDIR/turnserver.conf > /dev/null &
echo 'Running peer client'
$BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > /dev/null &

sleep 2

echo 'Running turn client TCP'
$BINDIR/turnutils_uclient -t -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi

echo 'Running turn client TLS'
$BINDIR/turnutils_uclient -t -S -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi

echo 'Running turn client UDP'
$BINDIR/turnutils_uclient -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1  | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi

echo 'Running turn client DTLS'
$BINDIR/turnutils_uclient -S -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1  | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi
