#!/bin/bash
for i in secure_udp_client.sh secure_dtls_client.sh secure_tcp_client_c2c_tcp_relay.sh  secure_tls_client_c2c_tcp_relay.sh secure_tls_client.sh secure_udp_client.sh secure_sctp_client.sh secure_tcp_client.sh secure_udp_c2c.sh;
do
	echo $i
	./scripts/longtermsecure/$i $@
done
