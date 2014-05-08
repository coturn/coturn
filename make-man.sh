#!/bin/sh

rm -rf man/man1/*

txt2man -s 1 -t TURN -I turnserver -I turnadmin -I turnutils -I turnutils_uclient -I turnutils_stunclient -I turnutils_rfc5769check -I turnutils_peer -B "TURN Server" README.turnserver | sed -e 's/-/\\-/g' > man/man1/turnserver.1

txt2man -s 1 -t TURN -I turnserver -I turnadmin -I turnutils -I turnutils_uclient -I turnutils_stunclient -I turnutils_rfc5769check -I turnutils_peer -B "TURN Server" README.turnadmin | sed -e 's/-/\\-/g'> man/man1/turnadmin.1

txt2man -s 1 -t TURN -I turnserver -I turnadmin -I turnutils -I turnutils_uclient -I turnutils_stunclient -I turnutils_rfc5769check -I turnutils_peer -B "TURN Server" README.turnutils | sed -e 's/-/\\-/g' > man/man1/turnutils.1

cd man/man1; ln -s turnutils.1 turnutils_uclient.1;cd ../..
cd man/man1; ln -s turnutils.1 turnutils_peer.1;cd ../..
cd man/man1; ln -s turnutils.1 turnutils_stunclient.1;cd ../..
cd man/man1; ln -s turnserver.1 coturn.1;cd ../..

