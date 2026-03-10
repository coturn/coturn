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


1) **Install PostgreSQL server**

	Check /etc/passwd file to find out which user account is used for the 
	PostgreSQL admin access on your system (it may be "pgsql", or "postgres", 
	or "postgresql"). 

	In the following examples, we'll assume that the user created by the Postgres installation is named 'postgres'.
	
	NOTE: The username 'postgres' is used in two contexts here!
	The first is the 'system' context (what you'd find in your `passwd` file), the other is the 'database' context (as a user within the 			postgres database, created by default).

	Immediately after the installation - initialize the postgres root database directory with the following commands:

	```
	$ sudo bash
	$ su -l postgres
	$ initdb -D /usr/local/pgsql/data
	```
  
3) **Find and edit Postgres' pg_hba.conf file to set the access options**

	Refer to Postgres documentation for most recent options available! 
	The Postgres documentation should be considered the authority in regards to configuration options and syntax!

	On different systems: the `pg_hba.conf` file may be located in different places.

	Set the lines for local access as "trust" for now (you can change it later), 
	for TCP/IP access set the value as "md5" or whatever password scheme you prefer.

	To set TCP/IP access from any host, use "0.0.0.0/0" for IPv4, and "::/0" 
	for IPv6.

5) **Edit postgresql.conf file to allow TCP/IP access** 

	Uncomment and edit the appropriate "listen_addresses" option (See Postgres documentation for options!).

	On different systems, this file may be located in different places - refer to your distribution documentation!
  
7) **Restart your system or restart the postgresql server**

    *On an Init.d system:*
   
	To Stop:

	`$ sudo /etc/init.d/postgresql stop`

	To Start:

	`$ sudo /etc/init.d/postgresql start`

	NOTE: The scripts may also be in /usr/local/etc/init.d, or in /etc/rc.d/, or
	in /usr/local/etc/rc.d/ .

	*On a SystemD system:*

	`$sudo systemctl restart postgresql`

	NOTE: The name of the service on a SystemD system may change depending on your package manager and postgres repo!
  
9) **Create a database for the TURN purposes named 'coturn'** 

	The database name for this example will be "coturn", and we will create it while using the 'postgres' database account:

   `$ createdb -U postgres coturn`
  
10) **Create a database user for the coturn database with username 'turn'**

	First, login to the 'coturn' database in postgres using the 'postgres' database user:
	`$ psql -U postgres -d coturn`
	
	Next: create the 'turn' user with the password 'turn':

	```
  	coturn=# create user turn with password 'turn';
	```
 
	Now we have a user named 'turn' with access to the 'coturn' database!
  
12) **Create the TURN users database schema**

	(See the SQLite section for the detailed database schema explanation.)

	The database schema for the TURN server is very minimalistic and is located 
	in project's turndb/schema.sql file, or in the system's 
	PREFIX/share/turnserver/schema.sql file after the turnserver installation:

	`$ cat turndb/schema.sql | psql -U turn -d coturn`

	NOTE:  CREATE TABLE / PRIMARY KEY will create implicit index "turnusers_lt_pkey" for table "turnusers_lt"
	NOTE: You may encounter issues with being unable to access or edit the schema 'public'.
	How you handle it is your decision - but it seems that the options are: "Give the turn user database ownership" or "Explicitly grant 			permissions to the turn user".
	
	
	To fill the database with test data:

	`cat turndb/testsqldbsetup.sql | psql -U turn -d coturn`

	You can use turnadmin program to manage the database - you can either use 
	turnadmin to add/modify/delete users, or you can use turnadmin to produce 
	the hmac keys and modify the database with your favorite tools.

	More examples of database schema creation:

     *Old style for 8.4:*

	`psql -h <host> -U <db-user> -d <database-name>  < turndb/schema.sql`
	
	
	*Newer style for 9.x, UNIX domain local sockets:*

	`psql postgresql://username:password@/databasename < turndb/schema.sql`

	*Newer style for 9.x, TCP/IP access:*

	`psql postgresql://username:password@hostname:port/databasename < turndb/schema.sql`

	When starting the turnserver, the psql-userdb parameter will be, for example:

	`turnserver ... --psql-userdb="host=localhost dbname=coturn user=turn password=turn connect_timeout=30"`

	*Or, for 9.x PostgreSQL versions:* 
	`turnserver ... --psql-userdb=postgresql://username:password@/databasename ...`
	In the context of our example database, the above string would be:
	`turnserver ... --psql-userdb=postgresql://postgresql://turn:turn@/turn ...`
  
13) **You are ready to use the TURN database!**

	The database name is "coturn",
	The user name is "turn", 
	The user password is "turn".

	Now, you will have to use the program turnadmin to fill the database, or you can do that manually with psql.

	Examples of adding users:

	Using a shared secret for the TURN REST API (realm north.gov):
  
  `$ bin/turnadmin -s logen -r north.gov -e "host=localhost dbname=coturn user=turn password=turn"`
  
  Using the long-term credentials mechanism:
  
  `$ bin/turnadmin -a -e "host=localhost dbname=coturn user=turn password=turn" -u gorst -r north.gov -p hero`
  `$ bin/turnadmin -a -e "host=localhost dbname=coturn user=turn password=turn" -u ninefingers -r north.gov -p youhavetoberealistic`
  
  Creating admin users:
  
   `$ bin/turnadmin -A -e "host=localhost dbname=coturn user=turn password=turn" -u gorst -p hero`
   `$ bin/turnadmin -A -e "host=localhost dbname=coturn user=turn password=turn" -u ninefingers -p youhavetoberealistic -r north.gov`

