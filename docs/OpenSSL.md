# OPENSSL

If you are using the OpenSSL that is coming with your system, and you are
OK with it, then you do not have to read this chapter. If your system has
an outdated OpenSSL version, or if you need some very fresh OpenSSL features
that are not present in the current usual stable version, then you may have
to compile (and run) your TURN server with a different OpenSSL version.

For example, if you need ALPN feature, or DTLS1.2, and your system comes with
OpenSSL 1.0.1, you will not be able to use those features unless you install
OpenSSL 1.0.2 and compile and run the TURN server with the newer version.

The problem is, it is usually not safe to replace the system's OpenSSL with
a different version. Some systems are "bound" to its "native" OpenSSL 
installations, and their behavior may become unpredictable with the newer
versions.

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
