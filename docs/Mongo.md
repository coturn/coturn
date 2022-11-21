# MongoDB setup

The MongoDB setup is well documented on their site http://docs.mongodb.org/manual/. 

Note: if your system has a "standard" plain vanilla UNIX "make" utility
(that is not a GNU make) then you will have to use the GNU make to compile 
the Mongo driver, because the Mongo compilation process was written with 
the "proprietary" GNU extensions. For example, in FreeBSD in will have to use 
"gmake" command. 

If the TURN server was compiled with MongoDB support (mongo-c-driver is the C client 
library for MongoDB), then we can use the TURN server database parameter 
--mongo-userdb. The value of this parameter is a connection string 
for the MongoDB database. The format of the connection string is described at 
http://hergert.me/docs/mongo-c-driver/mongoc_uri.html:

"mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]"

So, an example of the MongoDB database parameter in the TURN server command 
line would be:

--mongo-userdb="mongodb://localhost:27017/coturn"

Or in the turnserver.conf file:

mongo-userdb="mongodb://localhost:27017/coturn"

The meanings of the MongoDB keys are the same as for the other databases, see the 
explanations for the Postgres, for example.

See the file testmongosetup.sh for the database structure examples. 
