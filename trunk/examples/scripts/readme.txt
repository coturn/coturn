This directory contains various example scripts for the TURN server 
functionality illustration.

1) peer.sh starts the "peer" application that serves as a peer for all examples.

2) "basic" directory contains set of scripts which works together to demonstrate 
very basic anynymous functionality of the TURN server. The "peer.sh" must be used, too.

3) "longtermsecure" directory contains set of scripts demonstrating the long-term authentication
mechanism (peer.sh to be used, too).

4) "longtermsecuredb" shows how to start TURN server with database. The clients from the
directory "longtermsecure" can be used with the relay scripts in the "longtermsecuredb" 
directory. Of course, the database (PostgreSQL or MySQL) must be set for these scripts
to work correctly. 

5) "restapi" shows how to use TURN REST API.

6) "shorttermsecure" shows how to use the short-term authentication mechanism. The short term
mechanism is always used with the database.

7) "loadbalance" shows how to use the simple load-balancing mechanism based upon the
ALTERNATE-SERVER functionality.



