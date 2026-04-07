#	Coturn architecture, part 1 

##	Network architecture

### I. INTRODUCTION

This document assumes that the reader is familiar with the various TURN specifications.
The goal of this document is to provide general information for the Coturn
administrators and code developers about organization of the network interaction
in Coturn.

Coturn is a TURN relay server that has several general types of main network interaction:

1) Session establishment and maintenance negotiations with the client application.
2) Accepting packets to be relayed from the Client application, on the client-facing
sockets, and relaying those packets, through the relay sockets, to the Peer application.
3) Accepting packets to be relayed from the Peer application, on the peer-facing
relay sockets, and relaying those packets, through the Client sockets, to the Client
application.

There are other, secondary, interactions:

1) Communications with the database servers.
2) Communications with the telnet admin console.
3) Communications with the client admin browser, over HTTPS.

This document concentrates on the main network communications. It will describe
how those communicatiuons are organized in the Coturn code.

The key to the understanding how Coturn works is the notions of "listeners" and 
"general relay servers". 

### II. LISTENERS

In Coturn, a "listener" is the entity that initiates dialog with the new client. When a
new client sends its first packet to TURN, then it is initially accepted by the UDP
listener (the code in dtls_listener.c) or by TCP listener (the code in tls_listener.c).
The listeners are smart enough to recognize whether the new session is a TLS session or
"plain" protocol session, and it handles necessary SSL keys and negotiations.

The listener then creates a client endpoint (depending on the protocol and on the 
"network engine" - see below).

What happens next depends on the network engine. In the current implementation
(`NEV_UDP_SOCKET_PER_THREAD`), the listener and relay servers are paired within the same
thread, so the listener calls the session establishment function directly. See the function
open_client_connection_session() and where and how it is called in various cases,
for reference.

The listeners (and the relay servers) configuration is initiated in the function
setup_server() in netengine.c. First, setup_listener() creates the necessary generic 
data structures for the listeners. Second, network-engine-specific functions associate 
listeners with the execution threads and with the relay servers.

There may be multiple listeners in the server, and they may be running in different
threads.

### III. RELAY SERVERS

The relay servers take control over the client sessions after the initial contact was
established by the listeners. The relay server will be reading the session sockets
(the client and the relay sockets) and perform the necessary actions on them, according
to the TURN specs.

There can be multiple relay servers in the system, running in different threads.
The client sessions are distributed among them in fairly random manner, for load
balancing.

The relay server will be responsible for the session as long as the session exists.
It will exclusively handle all session communications. Thus, the session will stay
within the same thread for its lifetime. The performance benefit is that there will be
no CPU context switching when the session packets are handled.

There is one exception when a relay server will transfer a session to another relay
server: the mobility functionality. When the client address changes, it may require
that the session must be using a different thread - and a different relay server, as
the result. The the original relay server will have to pack the session, say
"farewell" to it and ship it to another relay server. The destination relay server
will adopt the session and the session will stay with the new relay server - until the
next client address change.

### IV. NETWORK ENGINE

Coturn uses a single network engine: `NEV_UDP_SOCKET_PER_THREAD`. In this model,
each thread owns one UDP socket per listener address. Multiple UDP and TCP listeners
and relay servers are bound to each frontend IP, with the listener and relay servers
paired and running in the same thread. This design eliminates cross-thread session
hand-offs for the common UDP path and delivers the best performance on modern kernels.

Previous releases supported two additional engine variants (a per-IP listener thread
model for older Linux and a BSD/Solaris model with separate listener and relay threads).
These have been removed; there is no longer an engine selection option.
