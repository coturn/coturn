
insert into turnusers_lt (realm, name, hmackey) values('north.gov','ninefingers','bc807ee29df3c9ffa736523fb2c4e8ee');
insert into turnusers_lt (realm, name, hmackey) values('north.gov','gorst','7da2270ccfa49786e0115366d3a3d14d');
insert into turnusers_lt (realm, name, hmackey) values('crinna.org','whirrun','6972e85e51f36e53b0b61759c5a5219a');
insert into turnusers_lt (realm, name, hmackey) values('crinna.org','stranger-come-knocking','d43cb678560259a1839bff61c19de15e');

insert into turnusers_st (name, password) values('ninefingers','youhavetoberealistic');
insert into turnusers_st (name, password) values('gorst','hero');
insert into turnusers_st (name, password) values('whirrun','sword');
insert into turnusers_st (name, password) values('stranger-come-knocking','civilization');

insert into turn_secret (realm,value) values('north.gov','logen');
insert into turn_secret (realm,value) values('crinna.org','north');

insert into admin_user (uname, realm, password) values('skarling','north.gov','hoodless');
insert into admin_user (uname, realm, password) values('bayaz','','magi');

insert into turn_origin_to_realm (origin,realm) values('http://crinna.org:80','crinna.org');
insert into turn_origin_to_realm (origin,realm) values('https://bligh.edu:443','crinna.org');

insert into turn_realm_option (realm,opt,value) values('north.gov','max-bps','500000');
insert into turn_realm_option (realm,opt,value) values('crinna.org','max-bps','400000');
insert into turn_realm_option (realm,opt,value) values('north.gov','total-quota','12000');
insert into turn_realm_option (realm,opt,value) values('crinna.org','total-quota','10000');
insert into turn_realm_option (realm,opt,value) values('north.gov','user-quota','10000');
insert into turn_realm_option (realm,opt,value) values('crinna.org','user-quota','8000');

insert into allowed_peer_ip (ip_range) values('172.17.13.200');
insert into allowed_peer_ip (realm,ip_range) values('north.gov','172.17.13.201');
insert into allowed_peer_ip (realm,ip_range) values('crinna.org','172.17.13.202');

insert into denied_peer_ip (ip_range) values('172.17.13.133-172.17.14.56');
insert into denied_peer_ip (ip_range) values('123::45');
insert into denied_peer_ip (realm,ip_range) values('north.gov','172.17.17.133-172.17.19.56');
insert into denied_peer_ip (realm,ip_range) values('crinna.org','123::77');

insert into oauth_key (kid,ikm_key,timestamp,lifetime,hkdf_hash_func,as_rs_alg,as_rs_key,auth_alg,auth_key) values('north','Y2FybGVvbg==',0,0,'SHA-256','AES-256-CBC','','HMAC-SHA-256-128','');
insert into oauth_key (kid,ikm_key,timestamp,lifetime,hkdf_hash_func,as_rs_alg,as_rs_key,auth_alg,auth_key) values('oldempire','YXVsY3Vz',0,0,'SHA-256','AEAD-AES-256-GCM','','','');
