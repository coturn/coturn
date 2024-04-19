# Redis setup

The Redis setup is well documented on their site http://redis.io. 
The TURN Server Redis database schema description can be found 
in schema.userdb.redis and schema.stats.redis files. Those files are located
either in the turndb subdirectory of the main source code directory,
or in /usr/local/share/turnserver/ after the installation, or somewhere in /usr/share/
directory, depending on the OS and on the installation package.

If the TURN server was compiled with Hiredis support (Hiredis is the C client 
library for Redis), then we can use the TURN server database parameter 
--redis-userdb. The value of this parameter is a connection string 
for the Redis database. As "native" Redis does not have such a feature as 
"connection string", the TURN server parses the connection string and 
converts it into Redis database access parameter. The format of the Redis 
connection string is:

"ip=<ip-addr> dbname=<database-number> password=<database-password> port=<port> connect_timeout=<seconds>"

(all parameters are optional)

So, an example of the Redis database parameter in the TURN server command 
line would be:

--redis-userdb="ip=127.0.0.1 dbname=2 password=turn connect_timeout=30"

Or in the turnserver.conf file:

redis-userdb="ip=127.0.0.1 dbname=2 password=turn connect_timeout=30"

Redis can be also used for the TURN allocation status check and for status and 
traffic notifications.

See the explanation in the turndb/schema.stats.redis file, and an example in 
turndb/testredisdbsetup.sh file. One special thing about TURN Redis security 
setup is that you can store open passwords for long-term credentials in Redis.
You cannot set open passwords for long-term credentials in SQLite or MySQL or
PostgreSQL - with those DBs, you have to use the keys only. With Redis, you 
have a choice - keys or open passwords.

You also have to take care about Redis connection parameters, the timeout and the 
keepalive. The following settings must be in your Redis config file
(/etc/redis.conf or /usr/local/etc/redis.conf):

..........
timeout 0
..........
tcp-keepalive 60
..........

Redis TURN admin commands:

  Shared secret for the TURN REST API (realm north.gov):
  
  $ bin/turnadmin -s logen -r north.gov -N "host=localhost dbname=2 user=turn password=turn"
  
  Long-term credentials mechanism:
  
  $ bin/turnadmin -a -N "host=localhost dbname=2 user=turn password=turn" -u gorst -r north.gov -p hero
  $ bin/turnadmin -a -N "host=localhost dbname=2 user=turn password=turn" -u ninefingers -r north.gov -p youhavetoberealistic
  
  Admin users:
   
  $ bin/turnadmin -A -N "host=localhost dbname=2 user=turn password=turn" -u gorst -p hero
  $ bin/turnadmin -A -N "host=localhost dbname=2 user=turn password=turn" -u ninefingers -p youhavetoberealistic -r north.gov
  
See the file testredisdbsetup.sh for the data structure examples.
