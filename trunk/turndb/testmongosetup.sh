#!/bin/sh

mongo $* <<EOF

use coturn;

db.turnusers_lt.insert({ realm: 'north.gov', name: 'ninefingers', hmackey: 'bc807ee29df3c9ffa736523fb2c4e8ee' });
db.turnusers_lt.insert({ realm: 'north.gov', name: 'gorst', hmackey: '7da2270ccfa49786e0115366d3a3d14d' });
db.turnusers_lt.insert({ realm: 'crinna.org', name: 'whirrun', hmackey: '6972e85e51f36e53b0b61759c5a5219a' });
db.turnusers_lt.insert({ realm: 'crinna.org', name: 'stranger-come-knocking', hmackey: 'd43cb678560259a1839bff61c19de15e' });

db.turnusers_st.insert({ name: 'ninefingers', password: 'youhavetoberealistic'});
db.turnusers_st.insert({ name: 'gorst', password: 'hero'});
db.turnusers_st.insert({ name: 'whirrun', password: 'sword'});
db.turnusers_st.insert({ name: 'stranger-come-knocking', password: 'civilization'});

db.turn_secret.insert({ realm: 'north.gov', value: 'logen' });
db.turn_secret.insert({ realm: 'crinna.org', value: 'north' });

db.realm.insert({
  realm: 'north.gov',
  options: {
    "max-bps" : 500000,
    "user-quota" : 10000,
    "total-quota" : 12000 
  }
});

db.realm.insert({
  realm: 'crinna.org',
  origin: [ 'http://crinna.org:80', 'https://bligh.edu:443' ],
  options: {
    "max-bps" : 400000,
    "user-quota" : 8000,
    "total-quota" : 10000 
  }
});

db.allowed_peer_ip.insert({ ip_range: '172.17.13.200' });

db.denied_peer_ip.insert({ ip_range: '172.17.13.133-172.17.14.56' });
db.denied_peer_ip.insert({ ip_range: '123::45' });

db.oauth_key.insert({ kid: 'north', 
					ikm_key: 'Y2FybGVvbg==', 
					hkdf_hash_func: 'SHA-256', 
					as_rs_alg: 'AES-256-CBC', 
					auth_alg: 'HMAC-SHA-256-128' });
					
db.oauth_key.insert({ kid: 'oldempire', 
					ikm_key: 'YXVsY3Vz', 
					hkdf_hash_func: 'SHA-256', 
					as_rs_alg: 'AEAD-AES-256-GCM', 
					auth_alg: '' });

exit

EOF
