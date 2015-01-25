This is Amazon EC2 system dedicated for Coturn TURN Server.
Before using it, you have to set the following parameters in 
/etc/turnserver.conf:

1) external-ip : use the public IP address assigned to your system.

2) Choose authentication option. This system is pre-set with the 
following options:

	a) long-term mechanism.

	b) SQLite is used as the default user database. 
	The pre-set database location is /usr/local/var/db/turndb.

	The pre-set database can be accessed from the command line as:

	$ sqlite3 /usr/local/var/db/turndb

	c) two test users are set for the default realm "north.gov":
		- user "ninefingers", with password "youhavetoberealistic";
		- user "gorst", with password "hero";

	d) two test users are set for the secondary realm "crinna.org":
		- user "whirrun" with password "sword";
		- user "stranger-come-knocking" with password "civilization";

	e) Default realm is set: "north.gov";

	f) shared secret for REST API is set as "logen", for the realm 
	"north.gov" (but REST API is not activated in /etc/turnserver.conf).

	g) shared secret for REST API is set as "north", for the realm 
	"crinna.org" (but REST API is not activated in /etc/turnserver.conf).

	h) two https web admin users are pre-set: superusers user "bayaz" with
	password "magi" and restricted (realm) admin user "skarling" with
	password "hoodless".

	You will have to choose the authentication option (long-term,
	or long-term with REST API, or no authentication).
	Then you will have to choose the user database option: 
	SQLite (pre-set by default here), or MySQL, 
	or PostgreSQL, or Redis, or MongoDB. 
	All five possible options are pre-set with the same data.
	Then you will have to remove the test users (manually or with the turnadmin 
	utility), and add  the real users.
	The turnadmin utility must be called with -b option for SQLite,
	-M option for MySQL, 
	-e option for PostgreSQL, -N option for Redis, -J for MongoDB.

3) Choose loging option. By default, the log file is /var/log/turn_*.log, in verbose mode. 
You can choose a different file prefix, or redirect the log into syslog. 

All question are to be sent to:

mom040267@gmail.com

Project page:

http://code.google.com/p/coturn/
 
Appendix A. Pre-set databases 
  (in addition to SQLite default database in /usr/local/var/db/turndb):

1) MySQL:

database name: turn
user: turn
password: turn

2) PostgreSQL:

database name: turn
user: turn
password: turn

3) Redis database for authentication

number: 0
password: turn

4) Redis database for status and statistics:

number: 1
password: turn

5) MongoDB for authentication

name: turn
no password is set.

All databases are accessible only locally, from the loopback interface, 
to eliminate the security threat. The user can change it if necessary, 
on his/her own risk.

Appendix B. Misc information about the default configuration details.

1) TURN server is configured as an automatically starting daemon.
See the daemon start/stop script in /etc/rc.d/init.d/coturn.

2) The default configured port is 3478.
If other port is needed, change the file /etc/turnserver.conf.

3) It is possible to configure multiple turnserver daemons on different ports,
and/or different IPs, and possible with different configuration parameters.
That can be done by using several daemon starting scripts, or with a single
complex script.
 
4) Additional information on the turn server usage can be found in the AMI in the
usual places:

/usr/local/share/turnserver/
/usr/local/share/doc/turnserver/
/usr/local/share/examples/turnserver/

And in the project web page:

https://code.google.com/p/coturn/

