# PostgreSQL setup

The site http://www.postgresql.org site has excellent extensive documentation. 
For a quick-start guide, you can take a look into this page: 
http://www.freebsddiary.org/postgresql.php. That page is written for 
FreeBSD users, but it has lots of generic information applicable to other 
*NIXes, too.

For the psql-userdb TURN server parameter, you can either set a PostgreSQL 
connection string, or a PostgreSQL URI, see the link:

For 8.4 PostgreSQL version:
http://www.postgresql.org/docs/8.4/static/libpq-connect.html

For newer 9.x versions: 
http://www.postgresql.org/docs/9.2/static/libpq-connect.html#LIBPQ-CONNSTRING.

In the PostgreSQL connection string or URI, you can set the host, the 
access port, the database name, the user, and the user password 
(if the access is secured). Numerous other parameters can be set, 
see the links above. The TURN server will blindly use that connection 
string without any modifications. You are responsible for the right 
connection string format.

Below are the steps to setup the PostgreSQL database server from scratch:

1) Install PostgreSQL server. After the installation, do not forget to
initialize the postgres root database directory:

	$ sudo bash
	$ su -l pgsql
	$ initdb -D /usr/local/pgsql/data

2) Find and edit Postgres' pg_hba.conf file to set the access options 
(see docs). On different systems, it may be located in different places.
Set the lines for local access as "trust" for now (you can change it later), 
for TCP/IP access set the value as "md5".
To set TCP/IP access from any host, use "0.0.0.0/0" for IPv4, and "::/0" 
for IPv6.

3) Edit postgresql.conf file to allow TCP/IP access - uncomment and edit 
the "listen_addresses" option (see docs). On different systems, this file 
may be located in different places.

4) Restart your system or restart the postgresql server, for example:

  $ sudo /etc/init.d/postgresql stop
  $ sudo /etc/init.d/postgresql start
  
  The scripts may also be in /usr/local/etc/init.d, or in /etc/rc.d/, or
  in /usr/local/etc/rc.d/ .

5) Check /etc/passwd file to find out which user account is used for the 
PostgreSQL admin access on your system (it may be "pgsql", or "postgres", 
or "postgresql"). Let's assume that this is "postgres" account.

6) Create a database for the TURN purposes, with name, say, "turn":

   $ createdb -U postgres coturn

7) Create a user for the TURN with name, say, "turn":
   $ psql -U postgres coturn
     turn=# create user turn with password 'turn';
     turn=# 
     Ctrl-D

8) Create the TURN users database schema.

The database schema for the TURN server is very minimalistic and is located 
in project's turndb/schema.sql file, or in the system's 
PREFIX/share/turnserver/schema.sql file after the turnserver installation:

$ cat turndb/schema.sql | psql -U turn -d coturn
	NOTICE:  CREATE TABLE / PRIMARY KEY will create implicit index "turnusers_lt_pkey" for table "turnusers_lt"
	CREATE TABLE
	CREATE TABLE

See the SQLite section for the detailed database schema explanation.

To fill the database with test data:

cat turndb/testsqldbsetup.sql | psql -U turn -d coturn

You can use turnadmin program to manage the database - you can either use 
turnadmin to add/modify/delete users, or you can use turnadmin to produce 
the hmac keys and modify the database with your favorite tools.

More examples of database schema creation:

psql -h <host> -U <db-user> -d <database-name>  < turndb/schema.sql
(old style for 8.4)

psql postgresql://username:password@/databasename < turndb/schema.sql
(newer style for 9.x, UNIX domain local sockets)

Or:

psql postgresql://username:password@hostname:port/databasename < turndb/schema.sql
(newer style for 9.x, TCP/IP access)

Below, the string "postgresql://turn:turn@/turn" is the connection URI. 
Of course, the administrators can play with the connection string as they want.

When starting the turnserver, the psql-userdb parameter will be, for example:

turnserver ... --psql-userdb="host=localhost dbname=coturn user=turn password=turn connect_timeout=30"

Or, for 9.x PostgreSQL versions: 
turnserver ... --psql-userdb=postgresql://username:password@/databasename ...

9) You are ready to use the TURN database. The database name is "turn",
the user name is "turn", the user password is "turn". Of course, you can 
choose your own names. Now, you will have to use the program turnadmin to fill the 
database, or you can do that manually with psql.

Fill in users, for example:

  Shared secret for the TURN REST API (realm north.gov):
  
  $ bin/turnadmin -s logen -r north.gov -e "host=localhost dbname=coturn user=turn password=turn"
  
  Long-term credentials mechanism:
  
  $ bin/turnadmin -a -e "host=localhost dbname=coturn user=turn password=turn" -u gorst -r north.gov -p hero
  $ bin/turnadmin -a -e "host=localhost dbname=coturn user=turn password=turn" -u ninefingers -r north.gov -p youhavetoberealistic
  
  Admin users:
   
  $ bin/turnadmin -A -e "host=localhost dbname=coturn user=turn password=turn" -u gorst -p hero
  $ bin/turnadmin -A -e "host=localhost dbname=coturn user=turn password=turn" -u ninefingers -p youhavetoberealistic -r north.gov

