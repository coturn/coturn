SQLite setup

The site http://www.sqlite.org site has excellent extensive documentation. 

The default SQLite database location for the TURN Server is 
/usr/local/var/db/turndb or /var/db/turndb (depending on the platform).

The database schema for the TURN server is very minimalistic and is located 
in project's turndb/schema.sql file, or in the system's 
PREFIX/share/turnserver/schema.sql file after the turnserver installation:

If you would like to created a new fresh SQLite TURN database:

$ `sqlite3 <your-db-file-name> < turndb/schema.sql`

The schema description:
```
# Table for long-term credentials mechanism authorization:
#
CREATE TABLE turnusers_lt (
    realm varchar(127) default '',
    name varchar(512),
    hmackey char(128),
    PRIMARY KEY (realm,name)
);
```

The field hmackey contains HEX string representation of the key.
We do not store the user open passwords for long-term credentials, for
security reasons. Storing only the HMAC key has its own implications - 
if you change the realm, you will have to update the HMAC keys of all 
users, because the realm is used for the HMAC key generation.

The key must be up to 32 characters (HEX representation of 16 bytes) for SHA1:
```
# Table holding shared secrets for secret-based authorization
# (REST API). Shared secret can be stored either in unsecure open
# plain form, or in encrypted form (see turnadmin docs).
# It can only be used together with the long-term 
# mechanism:
#
CREATE TABLE turn_secret (
	realm varchar(127) default '',
    value varchar(127),
	primary key (realm,value)
);

# Table holding "white" allowed peer IP ranges.
#
CREATE TABLE allowed_peer_ip (
	realm varchar(127) default '',
	ip_range varchar(256),
	primary key (realm,ip_range)
);

# Table holding "black" denied peer IP ranges.
#
CREATE TABLE denied_peer_ip (
	realm varchar(127) default '',
	ip_range varchar(256),
	primary key (realm,ip_range)
);

# Table to match origin to realm.
# Multiple origins may have the same realm.
# If no realm is found or the origin is absent
# then the default realm is used.
#
CREATE TABLE turn_origin_to_realm (
	origin varchar(127),
	realm varchar(127),
	primary key (origin,realm)
);

# Realm options.
# Valid options are 'max-bps',
# 'total-quota' and 'user-quota'.
# Values for them are integers (in text form).
#
CREATE TABLE turn_realm_option (
	realm varchar(127) default '',
	opt varchar(32),
	value varchar(128),
	primary key (realm,opt)
);

# oAuth key storage table.
#
CREATE TABLE oauth_key (
	kid varchar(128), 
	ikm_key varchar(256),
	timestamp bigint default 0,
	lifetime integer default 0,
	as_rs_alg varchar(64) default '',
	realm varchar(127) default '',
	primary key (kid)
); 
```

The oauth_key table fields meanings are:

	kid: the kid of the key;

	ikm_key - base64-encoded key ("input keying material");
		
	timestamp - (optional) the timestamp (in seconds) when the key 
		lifetime starts;
	
	lifetime - (optional) the key lifetime in seconds; the default value 
		is 0 - unlimited lifetime.
		
	as_rs_alg - oAuth token encryption algorithm; the valid values are
		"A256GCM", "A128GCM" (see 
		http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-5.1).
		The default value is "A256GCM";
	
	realm - (optional) can be used to set the user realm (if the field is not empty).
```
# Https access admin users.
# Leave this table empty if you do not want 
# remote https access to the admin functions.
# Web user password can be stored either in unsecure open
# plain form, or in encrypted form (see turnadmin docs).
#
CREATE TABLE admin_user (
	name varchar(32),
	realm varchar(127),
	password varchar(127),
	primary key (name)
);
```

You can use turnadmin program to manage the database - you can either use 
turnadmin to add/modify/delete users, or you can use turnadmin to produce 
the hmac keys and modify the database with your favorite tools.

When starting the turnserver, the --db parameter will be, for example:

`turnserver ... --db="/var/db/turndb"`

You will have to use the program turnadmin to fill the 
database, or you can do that manually with psql.

Fill in users, for example:

  Shared secret for the TURN REST API (realm north.gov):
  
  $ `bin/turnadmin -s logen -r north.gov -b "/var/db/turndb"`
  
  Long-term credentials mechanism:
  
  $ `bin/turnadmin -a -b "/var/db/turndb" -u gorst -r north.gov -p hero` \
  $ `bin/turnadmin -a -b "/var/db/turndb" -u ninefingers -r north.gov -p youhavetoberealistic`
  
  Admin users:
   
  $ `bin/turnadmin -A -b "/var/db/turndb" -u gorst -p hero` \
  $ `bin/turnadmin -A -b "/var/db/turndb" -u ninefingers -p youhavetoberealistic -r north.gov`
