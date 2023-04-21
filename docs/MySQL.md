# MySQL (MariaDB) setup

The MySQL setup is similar to PostgreSQL (the same idea), and is well documented 
on their site http://www.mysql.org. The TURN Server database schema is the 
same as for PostgreSQL and you can find it in turndb/schema.sql file, or 
in the system's PREFIX/share/turnserver/schema.sql file after the turnserver 
installation.

The general setup is similar to PostgreSQL setup procedure:

1) Check that the mysql server access is OK. Immediately after the MySQL server 
installation, it must be accessible, at the very minimum, at the localhost with
the root account.

2) Login into mysql console from root account:

  $ sudo bash
  # mysql mysql
  
(or mysql -p mysql if mysql account password set)
  
3) Add 'turn' user with 'turn' password (for example):

  > create user 'turn'@'localhost' identified by 'turn';
  
4) Create database 'coturn' (for example) and grant privileges to user 'turn':

  > create database coturn character set latin1;
  > grant all on coturn.* to 'turn'@'localhost';
  > flush privileges;
  Ctrl-D
  
5) Create database schema:

  $ mysql -p -u turn coturn < turndb/schema.sql
  Enter password: turn
  $
  
  Fill in test database data, if this is a test database
  (not a production database):
  
  $ mysql -p -u turn coturn < turndb/testsqldbsetup.sql
  
6) Fill in users, for example:

  Shared secret for the TURN REST API (realm north.gov):
  
  $ bin/turnadmin -s logen -r north.gov -M "host=localhost dbname=coturn user=turn password=turn"
  
  Long-term credentials mechanism:
  
  $ bin/turnadmin -a -M "host=localhost dbname=coturn user=turn password=turn" -u gorst -r north.gov -p hero
  $ bin/turnadmin -a -M "host=localhost dbname=coturn user=turn password=turn" -u ninefingers -r north.gov -p youhavetoberealistic
  
  Admin users:
   
  $ bin/turnadmin -A -M "host=localhost dbname=coturn user=turn password=turn" -u gorst -p hero
  $ bin/turnadmin -A -M "host=localhost dbname=coturn user=turn password=turn" -u ninefingers -p youhavetoberealistic -r north.gov

7) Now we can use mysql in the turnserver.

If the TURN server was compiled with MySQL support, then we can use the 
TURN server database parameter --mysql-userdb. The value of this parameter 
is a connection string for the MySQL database. As "native" MySQL does not 
have such a feature as "connection string", the TURN server parses the 
connection string and converts it into MySQL database connection parameter. 
The format of the MySQL connection string is:

"host=<host> dbname=<database-name> user=<database-user> password=<database-user-password> port=<port> connect_timeout=<seconds> read_timeout=<seconds>"

(all parameters are optional)

So, an example of the MySQL database parameter in the TURN server command 
line would be:

--mysql-userdb="host=localhost dbname=coturn user=turn password=turn connect_timeout=30 read_timeout=30"

Or in the turnserver.conf file:

mysql-userdb="host=localhost dbname=coturn user=turn password=turn connect_timeout=30 read_timeout=30"

If you have to use a secure MySQL connection (SSL) then you have to use also
the optional connection string parameters for the secure communications:
ca, capath, cert, key, cipher (see 
http://dev.mysql.com/doc/refman/5.1/en/ssl-options.html for the 
command options description).
