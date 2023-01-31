# Build

## Using autoconfigure build

If you are sure that you system is ready for the build (see the section 
"Extra libraries and Utilities" below) then you can build the system.
First, you have to run the configure script:

	$ cd turnserver-*
	$ ./configure
	
It will create a Makefile customized for your system. 

By default, the generated Makefile will install everything to:

	- /usr on Solaris.
	- /usr/pkg on NetBSD.
	- /usr/local everywhere else.

The binaries will be copied to the bin subdirectory of the installation 
destination, config files copied to etc subdirectory. The default SQLite database
will be created in var/db/turndb. There will be 
also documents, examples and some other files, in separate directories.

You can change the root configured destination directory by 
setting PREFIX variable in the 
configure command line. For example:

	$ PREFIX=/opt ./configure
	
Or:

	$ ./configure --prefix=/opt   

 You can change the auxiliary configured destination sub-directories by 
setting BINDIR, CONFDIR, MANPREFIX, EXAMPLESDIR, DOCSDIR, LIBDIR, SCHEMADIR,
LOCALSTATEDIR, TURNDBDIR and TURNINCLUDEDIR variables in the 
configure command line. For example:

	$ PREFIX=/opt BINDIR=/opt/bin64 CONFDIR=/opt/conf ./configure
	
Or:

	$ ./configure --prefix=/opt --bindir=/opt/bin64 --confdir=/opt/conf 

 You also can change the compilation and link options by 
setting common build variables in the 
configure command line. For example:

	$ CC=clang CFLAGS=-D_CAURIB LDFLAGS=-lshanka ./configure --prefix=/opt/shy

See below a separate INSTALL section for more details.

The script "configure" is a proprietary script. It will create a Makefile 
that you can use to build the project:

	$ make

The make command without options will do the following:
 - compile the code.
 - create bin/ sub-directory and put the TURN server, TURN admin and 
 "utility" programs there.
 - create lib/ sub-directory and put the client library there.
 - create include/turn/ sub-directory and put include files there.
 - create sqlite/turndb default empty database that will be copied to 
 var/db/ during the installation.

The TURN programs can be either called directly, or a shell scripts can be used. 
The script examples are located in examples/scripts directory. These scripts 
are just examples: you can run them successfully for the tests, but
you will have to change the script parameters for your real environment.

The command:

	$ sudo make install 

will install everything into the system file structure (see below).

(NOTE: On NetBSD, use "su root -c").

The command:

	$ sudo make deinstall
	
will remove all installed TURN Server files from your system.

The command:

	$ make clean 
	
will clean all results of the build and configuration actions.

Do not run "make clean" before "make deinstall". The "clean" command will
remove the Makefile and you will not be able to "deinstall" then. If that 
has happened, then run ./configure and make again, then deinstall and then 
clean.

NOTE: On most modern systems, the build will produce dynamically linked 
executables. If you want statically linked executables, you have to modify, 
accordingly, the Makefile.in template file.

## Using cmake build

If you are sure that you system is ready for the build (see the section 
"Extra libraries and Utilities" below) and cmake tools then you can build
the system.
First, create build directory. you have to run the follow script:

        $ cd coturn
        $ mkdir build

Then you have to run the configure script:

        $ cmake .. 

It will create a Makefile customized for your system. 

By default, the generated Makefile will install everything to:

	- /usr on Solaris.
	- /usr/pkg on NetBSD.
	- /usr/local everywhere else.

The binaries will be copied to the bin subdirectory of the installation 
destination, config files copied to etc subdirectory. The default SQLite database
will be created in var/db/turndb. There will be 
also documents, examples and some other files, in separate directories.

You can change the root configured destination directory by 
setting CMAKE_INSTALL_PREFIX variable in the 
configure command line. For example:

        $ cmake .. -DCMAKE_INSTALL_PREFIX=/opt

Build the project:

	$ cmake --build . 

Install all files(runtime programmes and develop library):

        $ cmake --build . --target install

Remove all installed:

        $ cmake --build . --target uninstall

If you want to only install runtime programmes(programmes, configure files,
script files and database):

        $ cmake --build . --target install-runtime

Remove all installed:

        $ cmake --build . --target uninstall-runtime


# INSTALL

This step is optional. You can run the turnserver from the original build 
directory, successfully, without installing the TURN server into your system. 
You have to install the turnserver only if you want to integrate the 
turnserver in your system.

Run the command:

$ make install

It will install turnserver in /usr/local/ directory (or to whatever directory
was set in the PREFIX variable). You will have to copy 
/usr/local/etc/turnserver.conf.default to /usr/local/etc/turnserver.conf file 
and adjust your runtime configuration.

This command will also:

 - copy the content of examples subdirectory into 
 PREFIX/share/examples/turnserver/ directory;
 - copy the generated default empty SQLite database from sqlite/turndb
 to /usr/local/var/db or to /var/db/turndb;
 - copy the content of include/turn subdirectory into
 PREFIX/include/turn/ directory;
 - copy the database schema file turndb/schema.sql into 
 PREFIX/share/turnserver/
 directory;
 - copy all docs into PREFIX/share/doc/turnserver/ directory.
 
The installation destination of "make install" can be changed by
using DESTDIR variable, for example:

 $ ./configure --prefix=/usr
 $ make
 $ make DESTDIR=/opt install
 
In this example, the root installation directory will be /opt/usr.  

The "configure" script by default generates a Makefile with "rpath" option
set for the dynamic libraries linking (if your system and your compiler 
allow that option). If that is not desirable (like in some OS packaging
procedures), then run the "configure" script with --disable-rpath option.

If you are not using the rpath linking option, then after the installation, 
you may have to adjust the system-wide shared library search path with
"ldconfig -n <libdirname>" (Linux), "ldconfig -m <libdirname>" (BSD) or 
"crle -u -l <libdirname>" (Solaris). Your system must be able to find the 
libevent2, openssl and (optionally) SQLite and/or PostgreSQL and/or MySQL 
(MariaDB) and/or MongoDB and/or Redis shared libraries, either with the 
help of the system-wide library search configuration or by using 
LD_LIBRARY_PATH. "make install" will make a non-guaranteed effort to add 
automatically PREFIX/lib and /usr/local/lib to the libraries search path, 
but if you have some libraries in different non-default directories then
you will have to add them manually to the search path, or you will have 
to adjust LD_LIBRARY_PATH.



# WHICH EXTRA LIBRARIES AND UTILITIES YOU NEED 

In addition to common *NIX OS services and libraries, to compile this code, 
OpenSSL (version 1.0.0a or better recommended) and libevent2 (version 2.0.5 
or better) are required, SQLite C development library and header is optional,
the PostgreSQL C client development setup is optional, 
the MySQL (MariaDB) C client development setup is optional, 
the MongoDB C Driver and the Hiredis development files for Redis database 
access are all optional. For development build, the development headers and 
the libraries to link with, are to be installed. For the runtime, only the 
runtime setup is required. If the build is modified for 
static linking, then even runtime installation is not needed.

OpenSSL, SQLite, libevent2, PostgreSQL, MySQL (or MariaDB) and Hiredis 
libraries can be downloaded from their web sites:
 - http://www.openssl.org (required);
 - http://www.libevent.org (required);
 - http://www.sqlite.org (optional);
 - http://www.postgresql.org (optional);
 - http://www.mysql.org (or http://mariadb.org) (optional);
 - https://github.com/mongodb/mongo-c-driver (optional);
 - http://redis.io (optional).
 
The installations are pretty straightforward - the usual 
"./configure" and "make install" commands. Install them into their default 
locations - the configure script and the Makefile are assuming that they are 
installed in their default locations. If not, then you will have to modify 
those.

Most modern popular systems (FreeBSD, Linux Ubuntu/Debian/Mint, Amazon Linux, Fedora) 
have a simpler way of the third party tools installation:      

	*) FreeBSD (the FRESH ports database is assumed to be installed, with
		the turnserver port included):

		$ cd /usr/ports/net/turnserver
		$ sudo make install clear

		That's it - that command will install the TURN server with all necessary
		third-party tools.

		If you system have no fresh ports repository:

		$ cd /usr/ports/security/openssl/
		$ sudo make install clean
		$ cd /usr/ports/databases/sqlite3/
		$ sudo make install clean
		$ cd /usr/ports/devel/libevent2/
		$ sudo make install clean
		$ cd /usr/ports/databases/postgresql84-client/ (or any other version)
		$ sudo make install clean
		$ cd /usr/ports/databases/mysql51-client/ (or any other version)
		$ sudo make install clean
		$ cd /usr/ports/databases/hiredis/
		$ sudo make install clean

	**) Linux Ubuntu, Debian, Mint:
		
		$ sudo apt-get install libssl-dev
		$ sudo apt-get install libsqlite3 (or sqlite3)
		$ sudo apt-get install libsqlite3-dev (or sqlite3-dev)
		$ sudo apt-get install libevent-dev
		$ sudo apt-get install libpq-dev
		$ sudo apt-get install mysql-client
		$ sudo apt-get install libmysqlclient-dev
		$ sudo apt-get install libhiredis-dev
		
		or you can use Synaptic or other software center.

	***) Fedora:

	$ sudo yum install openssl-devel
	$ sudo yum install sqlite
	$ sudo yum install sqlite-devel
	$ sudo yum install libevent
	$ sudo yum install libevent-devel
	$ sudo yum install postgresql-devel
	$ sudo yum install postgresql-server
	$ sudo yum install mysql-devel
	$ sudo yum install mysql-server
	$ sudo yum install hiredis
	$ sudo yum install hiredis-devel

	****) Amazon Linux is similar to Fedora, but:

	- you have to install gcc first:
		$ sudo yum install gcc

	- mongo-c-driver packages are not available "automatically". 
	MongoDB support will not be compiled, unless you install it "manually"
	before the TURN server compilation. Refer to 
	https://github.com/mongodb/mongo-c-driver for installation instructions
	of the driver.
		
	- hiredis packages are not available, so do not issue the 
	hiredis installation commands. Redis support will not be 
	compiled, unless you install it "manually" before the TURN 
	server compilation. For Amazon EC2 AMIs, we install the 
	redis manually in the system. But the TURN server can be 
	perfectly installed without redis support - if you do not 
	need it.
		
	*****) Older Debian family Linuxes are using some packages 
	with different names. 
		 
	******) On some CentOS / RedHat 6.x systems you have to install 
	libevent2 "manually", and optionally you have to download and 
	install Hiredis, but everything else can be found in the software 
	repository. Also, if you would like to make an RPM for CentOS,
	check the directory rpm/ with the instructions.

NOTE: If your tools are installed in non-standard locations, you will 
have to adjust CFLAGS and LDFLAGS environment variables for TURN 
server ./configure script. For example, to configure the TURN server 
with Solaris 11 PostgreSQL 32-bits setup, you may use a command 
like this:

  $ CFLAGS="${CFLAGS} -I/usr/postgres/9.2-pgdg/include/" LDFLAGS="${LDFLAGS} -L/usr/postgres/9.2-pgdg/lib/" ./configure

Dynamic library paths:

You may also have to adjust the turn server start script, add all the dynamic runtime 
library paths to LD_LIBRARY_PATH. Or you may find that it would be more convenient to adjust the 
system-wide shared library search path by using commands:

on Linux:

  $ ldconfig -n <libdirname> 

or on BSD:

  $ ldconfig -m <libdirname>

or on Solaris:

  $ crle -u -l <libdirname>

On Mac OS X, you have three different choices for dynamic libraries handling:

1) Use DYLD_LIBRARY_PATH environment variable in runtime; OR

2) Before the compilation, check the dynamic libraries and adjust their identification names,
if necessary, to the absolute library path or to @rpath/<library-file-name>. 
For example, the MySQL dynamic library may need that adjustment. You will have to use 
"adjust_name_tool" with -id option for that; OR

3) After the compilation, you can use the same tool, "adjust_name_tool", 
with option -change, to adjust the library paths values in the binary, 
where necessary. All library paths must be absolute paths or @rpath/... .

See also the next section.

NOTE: See "SQLite setup" and "PostgreSQL setup" and "MySQL setup" and 
"MongoDB setup" and "Redis setup" sections below for more database setup 
information.

NOTE: If you do not install SQLite or PostgreSQL or MySQL or MongoDB or Redis,
then you will be limited to the command-line options for user database. 
It will work great for development setup, but for real runtime systems you 
will need SQLite or PostgreSQL or MySQL or MongoDB or Redis.

NOTE: To run PostgreSQL or MySQL or MongoDB or Redis server on the same system, 
you will also have to install a corresponding PostgreSQL or MySQL or 
MongoDB or Redis server package. The DB C development packages only provide 
development libraries, and client libraries only provide client 
access utilities and runtime libraries. The server packages may 
include everything - client, C development and server runtime.   

NOTE: OpenSSL to be installed before libevent2. When libevent2 is building, 
it is checking whether OpenSSL has been already installed, and which version 
of OpenSSL. If the OpenSSL is missed, or too old, then libevent_openssl 
library is not being created during the build, and you will not be able to 
compile the TURN Server with TLS support.

NOTE: An older libevent version, version 1.x.x, is often included in some *NIX 
distributions. That version has its deficiencies and is inferior to the newer 
libevent2, especially in the performance department. This is why we are 
not providing backward compatibility with the older libevent 1.x version. 
If you have a system with older libevent, then you have to install the new 
libevent2 from their web site. It was tested with older *NIXes 
(like FreeBSD 6.x) and it works just fine.

NOTE: SQLite must be of version 3.x.

NOTE: For extra security features (like DTLS)
support, OpenSSL version 1.0.0a or newer is recommended. Older versions do 
not support DTLS, reliably, in some cases. For example, the Debian 'Squeeze'
Linux supplies 0.9.8 version of OpenSSL, that does not work correctly with
DTLS over IPv6. If your system already has an older version of OpenSSL
installed (usually in directory /usr) then you may want to install your
newer OpenSSL "over" the old one (because it will most probably will not allow
removal of the old one). When installing the newer OpenSSL, run the OpenSSL's
configure command like this:

    $ ./config --prefix=/usr

that will set the installation prefix to /usr (without "--prefix=/usr" 
by default it would be installed to /usr/local). This is necessary if you 
want to overwrite your existing older OpenSSL installation.

IX. BUILDING WITH NON-DEFAULT PREFIX DIRECTORY

Say, you have an older system with old openssl and old libevent 
library and you do not want to change that, but you still want 
to build the turnserver.

Do the following steps:

1) Download new openssl from openssl.org.
2) Configure and build new openssl and install it into /opt:
  
    $ ./config --prefix=/opt
    $ make
    $ make install

3) Download the latest libevent2 from libevent.org, configure and install 
it into /opt:

    $ ./configure --prefix=/opt
    $ make
    $ make install

4) Change directory to coturn and build it:

    $ ./configure --prefix=/opt
    $ make

After that, you can either use it locally, or install it into /opt. 
But remember that to run it, you have to adjust your LD_LIBRARY_PATH, 
like that:

    $ LD_LIBRARY_PATH=/opt/lib ./bin/turnserver

An alternative would be adjusting the system-wide shared library search path 
by using 
 $ ldconfig -n <libdirname> (Linux) 
 $ ldconfig -m <libdirname> (BSD) 
 $ crle -u -l <libdirname> (Solaris)