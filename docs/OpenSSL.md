# OPENSSL

coturn requires **OpenSSL 3.0 or newer**. This is the supported target.
Older OpenSSL releases (1.x, 1.1.x, 0.9.x) and other libraries are **not
supported** and are **not tested or validated against** - do not build or
validate coturn with them. (Some individual features need a newer 3.x: for
example RFC 7250 raw public keys require OpenSSL 3.2.1 or newer.)

A downstream compatibility patch for building against the deprecated,
end-of-life OpenSSL 1.1.1 is kept under `patches/openssl-1.1.1/` for operators
who cannot yet move off 1.1.1, but it is unsupported and outside the tested
configuration.

If your system already ships OpenSSL 3.0 or newer, you do not have to read the
rest of this chapter. If it ships an older version, install a supported OpenSSL
(3.0+) under a non-default prefix and build coturn against it, as below.

The reason not to simply replace the system's OpenSSL is that some systems are
"bound" to their "native" OpenSSL installation, and their behavior may become
unpredictable if it is swapped out. So preserve the system OpenSSL and build
(and run) the TURN server against a separate, supported OpenSSL:

So you want to preserve your system's OpenSSL but you want to compile and to
run the TURN server with newer OpenSSL version. There are different ways to
do that. We are suggesting the following:

	1) Download the OpenSSL version from openssl.org.
	2) Let's assume that we want to install the "custom" OpenSSL into /opt.
	Configure and build OpenSSL as:
		$ ./config --prefix=/opt
		$ make
		$ make install
	Those commands will install OpenSSL into /opt, with static libraries (no 
	dynamic libraries).
	3) Build the TURN server:
		$ ./configure --prefix=/opt
		$ make
	Those commands will build the TURN server binaries, statically linked 
	against the newer OpenSSL.
	4) Then you can run the TURN server without setting the dynamic 
	libraries paths - because it has been linked statically against the newer
	OpenSSL libraries.
	
One potential problem is that libevent2 is using the OpenSSL, too. So, ideally,
to be 100% safe of all potential discrepancies in the runtime, we'd suggesting 
rebuilding libevent2 with the newer OpenSSL, too.
