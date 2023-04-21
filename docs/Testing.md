# TEST SCRIPTS

First of all, you can use the test vectors from RFC 5769 to double-check that the 
STUN/TURN message encoding algorithms work properly. Run the utility:

 $ cd examples
 $ ./scripts/rfc5769.sh
 
It will perform several protocol checks and print the results on the output. 
If anything has compiled wrongly (TURN Server, or OpenSSL libraries) 
then you will see some errors.

Now, you can perform the TURN functionality test (bare minimum TURN example).

If everything compiled properly, then the following programs must run 
together successfully, simulating TURN network routing in local loopback
networking environment:

Open two shell screens or consoles:

In shell number 1, run TURN server application:
 $ cd examples
 $ ./scripts/basic/relay.sh

In shell number 2, run test client application:

 $ cd examples
 $ ./scripts/basic/udp_c2c_client.sh

If the client application produces output and in approximately 22 seconds 
prints the jitter, loss and round-trip-delay statistics, then everything is 
fine.

There is another more complex test:

In shell number 1, run TURN server application:
 $ cd examples
 $ ./scripts/basic/relay.sh
 
In shell number 2, run "peer" application:
 $ cd examples
 $ ./scripts/peer.sh

In shell number 3, run test client application:

 $ cd examples
 $ ./scripts/basic/udp_client.sh (or ./scripts/basic/tcp_client.sh)

There is a similar set of examples/scripts/longtermsecure/* scripts for 
TURN environment with long-term authentication mechanism. This set of 
scripts is more complex, and checking the scripts options is useful for 
understanding how the TURN Server works:

In shell number 1, run secure TURN server application:
 $ cd examples
 $ ./scripts/longtermsecure/secure_relay.sh
 
In shell number 2, run "peer" application:
 $ cd examples
 $ ./scripts/peer.sh

In shell number 3, run secure test client application:

 $ cd examples
 $ ./scripts/longtermsecure/secure_udp_client.sh
  
 (or ./scripts/longtermsecure/secure_tcp_client.sh)
 (or ./scripts/longtermsecure/secure_tls_client.sh)
 (or ./scripts/longtermsecure/secure_dtls_client.sh)
 (or ./scripts/longtermsecure/secure_sctp_client.sh)
 (or ./scripts/longtermsecure/secure_udp_c2c.sh for "peerless" 
client-to-client communications)

The provided scripts are set for the local loopback communications, 
as an example and as a test environment. Real networking IPs must be 
used in real work environments. 

Try wireshark to check the communications between client, turnserver 
and the peer. 

Check the README.* files and the comments in the scripts relay.sh and 
secure_relay.sh as a guidance how to run the TURN server.
