#!/bin/sh

pushd man/man1 >/dev/null 2>&1
  rm -rf ~0/*.1

  for _tMB in {admin,server,utils} ;
    do
      txt2man -s 1 -t TURN \
        -I turn${_tMB} \
        -I turnadmin \
        -I turnutils \
        -I turnutils_uclient \
        -I turnutils_stunclient \
        -I turnutils_rfc5769check \
        -I turnutils_peer \
        -I turnutils_natdiscovery \
        -I turnutils_oauth \
        -B "TURN Server" ~1/README.turn${_tMB} | \
        sed -e 's/-/\\-/g' > turn${_tMB}.1 ;
    done

  for _tLNK in {uclient,peer,stunclient,natdiscovery,oauth} ;
    do
      ln -s turnutils.1 turnutils_${_tLNK}.1 ; 
    done

  ln -s turnserver.1 coturn.1 ;

popd >/dev/null 2>&1
