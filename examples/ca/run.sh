#!/bin/bash
#set -x
# key passwd: coTURN
cp /usr/lib/ssl/misc/CA.pl ./CA.pl
patch < CA.pl.diff
export OPENSSL_CONFIG="-config openssl.conf"
./CA.pl -newca

for i in "server" "client"; 
do
	./CA.pl -newreq-nodes
	./CA.pl -signCA
	mv newcert.pem turn_${i}_cert.pem
	mv newkey.pem turn_${i}_pkey.pem
	rm newreq.pem
done;
