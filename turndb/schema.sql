
CREATE TABLE turnusers_lt (
    realm varchar(512),
    name varchar(512),
    hmackey char(128),
    PRIMARY KEY (realm,name)
);

CREATE TABLE turnusers_st (
    name varchar(512) PRIMARY KEY,
    password varchar(512)
);

CREATE TABLE turn_secret (
	realm varchar(512),
    value varchar(512),
	primary key (realm,value)
);

CREATE TABLE allowed_peer_ip (
	ip_range varchar(256),
	primary key (ip_range)
);

CREATE TABLE denied_peer_ip (
	ip_range varchar(256),
	primary key (ip_range)
);

CREATE TABLE turn_origin_to_realm (
	origin varchar(512),
	realm varchar(512),
	primary key (origin)
);

CREATE TABLE turn_realm_option (
	realm varchar(512),
	opt varchar(32),
	value varchar(128),
	primary key (realm,opt)
);
