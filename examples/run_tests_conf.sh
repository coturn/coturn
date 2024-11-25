#!/bin/bash
echo 'Create turnserver.conf file'
echo "use-auth-secret" > ../bin/turnserver.conf
echo "static-auth-secret=secret" >> ../bin/turnserver.conf
echo "realm=north.gov" >> ../bin/turnserver.conf
echo "allow-loopback-peers" >> ../bin/turnserver.conf
echo "no-cli" >> ../bin/turnserver.conf
echo "cert=../examples/ca/turn_server_cert.pem" >> ../bin/turnserver.conf
echo "pkey=../examples/ca/turn_server_pkey.pem" >> ../bin/turnserver.conf

echo 'Running turnserver'
../bin/turnserver -c ../bin/turnserver.conf > /dev/null &
echo 'Running peer client'
../bin/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > /dev/null &

sleep 2

echo 'Running turn client TCP'
../bin/turnutils_uclient -t -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi

echo 'Running turn client TLS'
../bin/turnutils_uclient -t -S -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi

echo 'Running turn client UDP'
../bin/turnutils_uclient -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1  | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi

echo 'Running turn client DTLS'
../bin/turnutils_uclient -S -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1  | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi
