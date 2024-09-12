#!/bin/bash

echo 'Running turnserver'
../bin/turnserver --use-auth-secret  --static-auth-secret=secret --realm=north.gov --allow-loopback-peers --no-cli --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem > /dev/null &
echo 'Running peer client'
../bin/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > /dev/null &

sleep 5

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

killall -9 turnserver &> /dev/null
../bin/turnserver --use-auth-secret  --static-auth-secret=secret --realm=north.gov --allow-loopback-peers --no-cli --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem &> /tmp/coturn.log &

sleep 5

echo 'Running rate limit by IP'
../bin/turnutils_uclient  -e 127.0.0.1 -X -g -u user1 -W wrongsecret 127.0.0.1 > /dev/null
../bin/turnutils_uclient  -e 127.0.0.1 -X -g -u user1 -W wrongsecret 127.0.0.1 > /dev/null
../bin/turnutils_uclient  -e 127.0.0.1 -X -g -u user1 -W wrongsecret 127.0.0.1 > /dev/null
../bin/turnutils_uclient  -e 127.0.0.1 -X -g -u user1 -W wrongsecret 127.0.0.1 > /dev/null
../bin/turnutils_uclient  -e 127.0.0.1 -X -g -u user1 -W wrongsecret 127.0.0.1 > /dev/null &
sleep 5
grep '401 rate limit exceeded from' /tmp/coturn.log >/dev/null
if [ $? -eq 0 ]; then
    echo OK
else
    echo FAIL
    exit $?
fi

echo 'Running NOT rated limit by IP'
../bin/turnutils_uclient  -e 127.0.0.1 -X -g -u user1 -W wrongsecret 127.0.0.1 > /dev/null
../bin/turnutils_uclient  -e 127.0.0.1 -X -g -u user1 -W wrongsecret 127.0.0.1 > /dev/null &
sleep 5
grep '401 rate limit exceeded from' /tmp/coturn.log >/dev/null
if [ $? -eq 1 ]; then
    echo OK
else
    echo FAIL
	exit $?
fi
