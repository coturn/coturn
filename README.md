**_This project evolved from rfc5766-turn-server project (https://code.google.com/p/rfc5766-turn-server/). There are many new advanced TURN specs which are going far beyond the original RFC 5766 document. This project takes the code of rfc5766-turn-server as the starter, and adds new advanced features to it._**

[Downloads page](https://github.com/coturn/coturn/wiki/Downloads)

[Wiki pages](https://github.com/coturn/coturn/wiki/)

# Free open source implementation of TURN and STUN Server #

The TURN Server is a VoIP media traffic NAT traversal server and gateway. It can be used as a general-purpose network traffic TURN server and gateway, too.

On-line management interface (over telnet or over HTTPS) for the TURN server is available.

The implementation also includes some extra experimental features.

Supported RFCs:

TURN specs:

  * RFC 5766 - base TURN specs
  * RFC 6062 - TCP relaying TURN extension
  * RFC 6156 - IPv6 extension for TURN
  * RFC 7443 - ALPN support for STUN & TURN
  * RFC 7635 - oAuth third-party TURN/STUN authorization
  * DTLS support (http://tools.ietf.org/html/draft-petithuguenin-tram-turn-dtls-00).
  * Mobile ICE (MICE) support (http://tools.ietf.org/html/draft-wing-tram-turn-mobility-02).
  * TURN REST API (http://tools.ietf.org/html/draft-uberti-behave-turn-rest-00)
  * Origin field in TURN (Multi-tenant TURN Server) (https://tools.ietf.org/html/draft-ietf-tram-stun-origin-06)
  * TURN Bandwidth draft specs (http://tools.ietf.org/html/draft-thomson-tram-turn-bandwidth-01)
  * TURN-bis (with dual allocation) draft specs (http://tools.ietf.org/html/draft-ietf-tram-turnbis-04).

STUN specs:

  * RFC 3489 - "classic" STUN
  * RFC 5389 - base "new" STUN specs
  * RFC 5769 - test vectors for STUN protocol testing
  * RFC 5780 - NAT behavior discovery support
  * RFC 7443 - ALPN support for STUN & TURN
  * RFC 7635 - oAuth third-party TURN/STUN authorization

Supported ICE and related specs:

  * RFC 5245 - ICE
  * RFC 5768 – ICE–SIP
  * RFC 6336 – ICE–IANA Registry
  * RFC 6544 – ICE–TCP
  * RFC 5928 - TURN Resolution Mechanism

The implementation fully supports the following client-to-TURN-server protocols:

  * UDP (per RFC 5766)
  * TCP (per RFC 5766 and RFC 6062)
  * TLS (per RFC 5766 and RFC 6062): TLS1.0/TLS1.1/TLS1.2; ECDHE is supported.
  * DTLS  (http://tools.ietf.org/html/draft-petithuguenin-tram-turn-dtls-00): DTLS versions 1.0 and 1.2.
  * SCTP (experimental implementation).

Supported relay protocols:

  * UDP (per RFC 5766)
  * TCP (per RFC 6062)

Supported user databases (for user repository, with passwords or keys, if authentication is required):

  * SQLite
  * MySQL
  * PostgreSQL
  * Redis
  * MongoDB

Redis can also be used for status and statistics storage and notification.

Supported message integrity digest algorithms:

  * HMAC-SHA1, with MD5-hashed keys (as required by STUN and TURN standards)

Supported TURN authentication mechanisms:

  * 'classic' long-term credentials mechanism;
  * TURN REST API (a modification of the long-term mechanism, for time-limited secret-based authentication, for WebRTC applications: http://tools.ietf.org/html/draft-uberti-behave-turn-rest-00);
  * experimental third-party oAuth-based client authorization option;

When used as a part of an ICE solution, for VoIP connectivity, this TURN server can handle thousands simultaneous calls per CPU (when TURN protocol is used) or tens of thousands calls when only STUN protocol is used. For virtually unlimited scalability a load balancing scheme can be used. The load balancing can be implemented with the following tools (either one or a combination of them):

  * DNS SRV based load balancing;
  * built-in 300 ALTERNATE-SERVER mechanism (requires 300 response support by the TURN client);
  * network load-balancer server.

Traffic bandwidth limitation and congestion avoidance algorithms implemented.

The supported project target platforms are:

  * Linux (Debian, Ubuntu, Mint, CentOS, Fedora, Redhat, Amazon Linux, Arch Linux, OpenSUSE)
  * BSD (FreeBSD, NetBSD, OpenBSD, DragonFlyBSD)
  * Solaris 11
  * Mac OS X
  * Cygwin (for non-production R&D purposes)

Other server platforms can be supported by request.

Any client platform is supported, including Android, iOS, Linux, OS X, Windows, and Windows Phone.

This project can be successfully used on other `*NIX` platforms, too, but that is not officially supported.

The implementation is supposed to be simple, easy to install and configure. The project focuses on performance, scalability and simplicity. The aim is to provide an enterprise-grade TURN solution.

To achieve high performance and scalability, the TURN server is implemented with the following features:

  * High-performance industrial-strength Network IO engine libevent2 is used
  * Configurable multi-threading model implemented to allow full usage of available CPU resources (if OS allows multi-threading)
  * Multiple listening and relay addresses can be configured
  * Efficient memory model used
  * The TURN project code can be used in a custom proprietary networking environment. In the TURN server code, an abstract networking API is used. Only couple files in the project have to be re-written to plug-in the TURN server into a proprietary environment. With this project, only implementation for standard UNIX Networking/IO API is provided, but the  user can implement any other environment. The TURN server code was originally developed for a high-performance proprietary corporate environment, then adopted for UNIX Networking API
  * The TURN server works as a user space process, without imposing any special requirements on the system

To download the TURN Server software, the client messaging library and the test programs, click the tab "Downloads".

Contact information:

https://groups.google.com/forum/#!forum/turn-server-project-rfc5766-turn-server

email:mom040267@gmail.com

### Feedback is very welcome (bugs, issues, suggestions, stories, questions). ###

### Volunteers are welcome, too. ###
