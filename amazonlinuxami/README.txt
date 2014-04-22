This is Amazon EC2 system dedicated for rfc5766-turn-server TURN Server.
Before using it, you have to set the following parameters in /etc/turnserver.conf:

1) external-ip : use the public IP address assigned to your system.

2) Choose authentication option. This system is pre-set with the following options:
	a) long-term mechanism.
	b) MySQL is used as the user database.
	c) two test users are set:
		- ninefingers, with password "youhavetoberealistic";
		- gorst, with password "hero";
	d) test realm is set: north.gov;
	e) shared secret for REST API is set as "logen" (but REST API is not
	activated in /etc/turnserver.conf).
	f) The same two users are pre-set for the short-term authentication mechanism,
	but the short-term mechanism is not activated in /etc/turnserver.conf.

	You will have to choose the authentication option (long-term,
	or long-term with REST API, or short-term, or no authentication).
	Then you will have to choose the user database option: MySQL (set by default here), 
	or PostgreSQL, or flat file DB (/etc/turnuserdb.conf), or Redis. All four possible 
	databases are pre-set with the same data.
	Then you will have to remove the test users with the turnadmin utility, and add 
	the real users. The turnadmin utility must be called with -M option for MySQL, 
	-e option for PostgreSQL, -N option for Redis, or with -b option for flat DB file.

3) Choose loging option. By default, the log file is /var/log/turn_*.log, in verbose mode. 
You can choose a different file prefix, or redirect the log into syslog. 

All question are to be sent to:

mom040267@gmail.com

Project page:

http://code.google.com/p/rfc5766-turn-server/
 
Appendix A. Pre-set databases

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

All databases are accessible only locally, from the loopback interface, 
to eliminate the security threat. The user can change it if necessary, 
on his/her own risk.

Appendix B. Misc information about the default configuration details.

1) TURN server is configured as an automatically starting daemon.
See the daemon start/stop script in /etc/rc.d/init.d/rfc5766-turn-server.

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

https://code.google.com/p/rfc5766-turn-server/

