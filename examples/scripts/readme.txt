This directory contains various example scripts for the TURN server 
functionality illustration.

1) peer.sh starts the "peer" application that serves as a peer for all examples.

2) "basic" directory contains set of scripts which works together to demonstrate 
very basic anynymous functionality of the TURN server. The "peer.sh" must be used, too.

3) "longtermsecure" directory contains set of scripts demonstrating the long-term
authentication mechanism (peer.sh to be used, too).

4) "longtermsecuredb" shows how to start TURN server with database. The clients from the
directory "longtermsecure" can be used with the relay scripts in the "longtermsecuredb" 
directory. Of course, the database (SQLite, PostgreSQL, MySQL, Redis or MongoDB) must 
be set for these scripts to work correctly. 

5) "restapi" shows how to use TURN REST API.

6) "loadbalance" shows how to use the simple load-balancing mechanism based upon the
ALTERNATE-SERVER functionality.

7) "selfloadbalance" shows how to use the "self-load-balance" TURN server capabilities.

8) "mobile" shows the "mobile" connections - how the TURN session can change its client
address. 



