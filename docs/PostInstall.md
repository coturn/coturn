# Post Install

1) If your system supports automatic start-up system daemon services, 
then to enable the turnserver as a system service that is automatically
started, you have to:

	a) Create and edit /etc/turnserver.conf or 
	/usr/local/etc/turnserver.conf . 
	Use /usr/local/etc/turnserver.conf.default as an example.

	b) For user accounts settings: set up SQLite or PostgreSQL or 
	MySQL or MongoDB or Redis database for user accounts.
	Use /usr/local/share/turnserver/schema.sql as SQL database schema,
	or use /usr/local/share/turnserver/schema.userdb.redis as Redis
	database schema description and/or 
	/usr/local/share/turnserver/schema.stats.redis
	as Redis status & statistics database schema description.
	
	If you are using SQLite, the default database location is in 
	/var/db/turndb or in /usr/local/var/db/turndb or in /var/lib/turn/turndb.
	 
	c) add whatever is necessary to enable start-up daemon for the 
	/usr/local/bin/turnserver.
     
2) If you do not want the turnserver to be a system service, 
   then you can start/stop it "manually", using the "turnserver" 
   executable with appropriate options (see the documentation).
   
3) To create database schema, use schema in file 
/usr/local/share/turnserver/schema.sql.
   
4) For additional information, run:
 
   $ man turnserver
   $ man turnadmin
   $ man turnutils
	
==================================================================
 
