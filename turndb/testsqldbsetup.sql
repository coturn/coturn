
insert into turnusers_lt (realm, name, hmackey) values('north.gov','ninefingers','bc807ee29df3c9ffa736523fb2c4e8ee');
insert into turnusers_lt (realm, name, hmackey) values('north.gov','gorst','7da2270ccfa49786e0115366d3a3d14d');
insert into turnusers_lt (realm, name, hmackey) values('crinna.org','whirrun','6972e85e51f36e53b0b61759c5a5219a');
insert into turnusers_lt (realm, name, hmackey) values('crinna.org','stranger-come-knocking','d43cb678560259a1839bff61c19de15e');

insert into turn_secret (realm,value) values('north.gov','logen');
insert into turn_secret (realm,value) values('north.gov','bloody9');
insert into turn_secret (realm,value) values('crinna.org','north');
insert into turn_secret (realm,value) values('crinna.org','library');

insert into admin_user (name, realm, password) values('skarling','north.gov','$5$6fc35c3b0c7d4633$27fca7574f9b79d0cb93ae03e45379470cbbdfcacdd6401f97ebc620f31f54f2');
insert into admin_user (name, realm, password) values('bayaz','','$5$e018513e9de69e73$5cbdd2e29e04ca46aeb022268a7460d3a3468de193dcb2b95f064901769f455f');

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

insert into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values('north','MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEK',0,0,'A256GCM','crinna.org');
insert into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values('union','MTIzNDU2Nzg5MDEyMzQ1Ngo=',0,0,'A128GCM','north.gov');
insert into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values('oldempire','MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIK',0,0,'A256GCM','');
