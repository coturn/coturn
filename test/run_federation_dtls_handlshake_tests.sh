#!/bin/bash

TEST_SERVER=127.0.0.1:9191

SUCCESS=0
FAILURE=1

GoodRSACiphers=('ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',\
             'DHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA',\
             'ECDHE-RSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA', 'DHE-RSA-AES128-SHA256',\
             'DHE-RSA-AES128-SHA', 'DHE-RSA-AES256-SHA256', 'DHE-RSA-AES256-SHA')

GoodECDSACiphers=('ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-GCM-SHA384',\
             'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-ECDSA-AES128-SHA',\
             'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-ECDSA-AES256-SHA')

UnsupportedCiphers=('DHE-RSA-AES256-GCM-SHA384',\
             'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305', 'DHE-RSA-CHACHA20-POLY1305', 'RSA-PSK-AES256-GCM-SHA384',\
             'DHE-PSK-AES256-GCM-SHA384', 'RSA-PSK-CHACHA20-POLY1305', 'DHE-PSK-CHACHA20-POLY1305', 'ECDHE-PSK-CHACHA20-POLY1305',\
             'AES256-GCM-SHA384', 'PSK-AES256-GCM-SHA384', 'PSK-CHACHA20-POLY1305', 'RSA-PSK-AES128-GCM-SHA256',\
             'DHE-PSK-AES128-GCM-SHA256', 'AES128-GCM-SHA256', 'PSK-AES128-GCM-SHA256', 'AES256-SHA256',\
             'AES128-SHA256', 'ECDHE-PSK-AES256-CBC-SHA384', 'ECDHE-PSK-AES256-CBC-SHA', 'SRP-RSA-AES-256-CBC-SHA',\
             'SRP-AES-256-CBC-SHA', 'RSA-PSK-AES256-CBC-SHA384', 'DHE-PSK-AES256-CBC-SHA384', 'RSA-PSK-AES256-CBC-SHA',\
             'DHE-PSK-AES256-CBC-SHA', 'AES256-SHA', 'PSK-AES256-CBC-SHA384', 'PSK-AES256-CBC-SHA', 'ECDHE-PSK-AES128-CBC-SHA256',\
             'ECDHE-PSK-AES128-CBC-SHA', 'SRP-RSA-AES-128-CBC-SHA', 'SRP-AES-128-CBC-SHA', 'RSA-PSK-AES128-CBC-SHA256',\
             'DHE-PSK-AES128-CBC-SHA256', 'RSA-PSK-AES128-CBC-SHA', 'DHE-PSK-AES128-CBC-SHA', 'AES128-SHA',\
             'PSK-AES128-CBC-SHA256', 'PSK-AES128-CBC-SHA')

stop_server() {
  if [ ! -z "$serverPID" ] ; then
    kill $serverPID
    echo "Stopped server pid=$serverPID"
  fi
  serverPID=""
}

start_server() {
  stop_server
  nohup ../bin/turnserver -c $1 > $1.out 2>&1 &
  serverPID=$!
  sleep 1
  echo "Started server, pid=$serverPID, conf=$1"
}

check_result() {
  local result=$?
  if [ $result -eq $2 ] ; then
    echo "PASSED: $1"
  else
    echo "FAILED: $1"
    stop_server
    echo "Unit tests failed, exiting!"
    exit 1
  fi
}


###################################
# Positive Tests
###################################

#if false; then

# Start server with no issuer check enabled in config
start_server turnserver_rsa_noissuercheck.conf

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cert federation_rsa_cert.pem -key federation_rsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS version 1.2 federation client connects (no issuer check)" $SUCCESS

# Start server with default rsa config
start_server turnserver_rsa.conf

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cert federation_rsa_cert.pem -key federation_rsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS version 1.2 federation client connects" $SUCCESS

for cipher in "${GoodRSACiphers[@]}"; do
  echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cipher $cipher -cert federation_rsa_cert.pem -key federation_rsa_pkey.pem >/dev/null 2>/dev/null
  check_result "DTLS federation client good cipher $cipher connects" $SUCCESS
done

# Start server with default ecdsa config
start_server turnserver_ecdsa.conf

for cipher in "${GoodECDSACiphers[@]}"; do
  echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cipher $cipher -cert federation_ecdsa_cert.pem -key federation_ecdsa_pkey.pem >/dev/null 2>/dev/null
  check_result "DTLS federation client good cipher $cipher connects" $SUCCESS
done


###################################
# Negative Tests
###################################

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1 -cert federation_ecdsa_cert.pem -key federation_ecdsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS version 1 federation client fails to connect" $FAILURE

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cipher NULL,LOW -cert federation_ecdsa_cert.pem -key federation_ecdsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS federation client mismatched cipher list fails to connect" $FAILURE

for cipher in "${UnsupportedCiphers[@]}"; do
  echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cipher $cipher -cert federation_ecdsa_cert.pem -key federation_ecdsa_pkey.pem >/dev/null 2>/dev/null
  check_result "DTLS federation client unsupported cipher $cipher fails to connect" $FAILURE
done

start_server turnserver_ecdsa_mismatchdomain.conf

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cert federation_ecdsa_cert.pem -key federation_ecdsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS federation client mismatched domain check fails to connect" $FAILURE

start_server turnserver_ecdsa_mismatchissuer.conf

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cert federation_ecdsa_cert.pem -key federation_ecdsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS federation client mismatched issuer check fails to connect" $FAILURE

start_server turnserver_ecdsa_badca.conf

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cert federation_ecdsa_cert.pem -key federation_ecdsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS federation client with bad root CA fails to connect" $FAILURE

start_server turnserver_rsa.conf

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cert federation_rsa_expired_cert.pem -key federation_rsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS federation client expired cert fails to connect" $FAILURE

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cert federation_rsa_notyetvalid_cert.pem -key federation_rsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS federation client 'not yet valid' cert fails to connect" $FAILURE

echo "Q" | timeout 3 openssl s_client -connect $TEST_SERVER -dtls1_2 -cert federation_rsa_badsig_cert.pem -key federation_rsa_pkey.pem >/dev/null 2>/dev/null
check_result "DTLS federation client bad signature cert fails to connect" $FAILURE


# Stop the server
stop_server


