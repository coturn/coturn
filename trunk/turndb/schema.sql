
CREATE TABLE turnusers_lt (
    realm varchar(127) default '',
    name varchar(512),
    hmackey char(128),
    PRIMARY KEY (realm,name)
);

CREATE TABLE turn_secret (
	realm varchar(127) default '',
    value varchar(127),
	primary key (realm,value)
);

CREATE TABLE allowed_peer_ip (
	realm varchar(127) default '',
	ip_range varchar(256),
	primary key (realm,ip_range)
);

CREATE TABLE denied_peer_ip (
	realm varchar(127) default '',
	ip_range varchar(256),
	primary key (realm,ip_range)
);

CREATE TABLE turn_origin_to_realm (
	origin varchar(127),
	realm varchar(127),
	primary key (origin)
);

CREATE TABLE turn_realm_option (
	realm varchar(127) default '',
	opt varchar(32),
	value varchar(128),
	primary key (realm,opt)
);

CREATE TABLE oauth_key (
	kid varchar(128),
	ikm_key varchar(256) default '',
	timestamp bigint default 0,
	lifetime integer default 0,
	hkdf_hash_func varchar(64) default '',
	as_rs_alg varchar(64) default '',
	as_rs_key varchar(256) default '',
	auth_alg varchar(64) default '',
	auth_key varchar(256) default '',
	primary key (kid)
);

CREATE TABLE admin_user (
	name varchar(32),
	realm varchar(127),
	password varchar(127),
	primary key (name)
);