#!/bin/sh

# ninefingers:password: youhavetoberealistic
# gorst:password: hero
# whirrun:password: sword
# stranger-come-knocking:password: civilization
#
# bayaz admin user password: magi
# skarling admin user password: hoodless

mongo $* <<EOF

use coturn;

db.turnusers_lt.ensureIndex({ realm: 1, name: 1 }, { unique: 1 });
db.turn_secret.ensureIndex({ realm: 1, value:1 }, { unique: 1 });
db.realm.ensureIndex({ realm: 1 }, { unique: 1 });
db.oauth_key.ensureIndex({ kid: 1 }, {unique: 1 });
db.admin_user.ensureIndex({ name: 1 }, {unique: 1 });

db.turnusers_lt.insert({ realm: 'north.gov', name: 'ninefingers', hmackey: 'bc807ee29df3c9ffa736523fb2c4e8ee' });
db.turnusers_lt.insert({ realm: 'north.gov', name: 'gorst', hmackey: '7da2270ccfa49786e0115366d3a3d14d' });
db.turnusers_lt.insert({ realm: 'crinna.org', name: 'whirrun', hmackey: '6972e85e51f36e53b0b61759c5a5219a' });
db.turnusers_lt.insert({ realm: 'crinna.org', name: 'stranger-come-knocking', hmackey: 'd43cb678560259a1839bff61c19de15e' });

db.turn_secret.insert({ realm: 'north.gov', value: 'logen' });
db.turn_secret.insert({ realm: 'north.gov', value: 'bloody9' });
db.turn_secret.insert({ realm: 'crinna.org', value: 'north' });
db.turn_secret.insert({ realm: 'crinna.org', value: 'library' });

db.admin_user.insert({ name: 'skarling', realm: 'north.gov', password: '\$5\$6fc35c3b0c7d4633\$27fca7574f9b79d0cb93ae03e45379470cbbdfcacdd6401f97ebc620f31f54f2' });
db.admin_user.insert({ name: 'bayaz', realm: '', password: '\$5\$e018513e9de69e73\$5cbdd2e29e04ca46aeb022268a7460d3a3468de193dcb2b95f064901769f455f' });

db.realm.insert({
  realm: 'north.gov',
  options: {
    "max-bps" : 500000,
    "user-quota" : 10000,
    "total-quota" : 12000 
  },
  allowed_peer_ip: [ '172.17.13.200', '172.17.13.201' ],
  denied_peer_ip: ['172.17.13.133-172.17.14.56', '123::45', '172.17.17.133-172.17.19.56']
});

db.realm.insert({
  realm: 'crinna.org',
  origin: [ 'http://crinna.org:80', 'https://bligh.edu:443' ],
  options: {
    "max-bps" : 400000,
    "user-quota" : 8000,
    "total-quota" : 10000 
  },
  allowed_peer_ip: [ '172.17.13.200', '172.17.13.201' ],
  denied_peer_ip: ['172.17.13.133-172.17.14.56', '123::45', '123::77']
});

db.oauth_key.insert({ kid: 'north', 
					ikm_key: 'MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEK', 
					as_rs_alg: 'A256GCM',
					realm: 'crinna.org'});
db.oauth_key.insert({ kid: 'union', 
					ikm_key: 'MTIzNDU2Nzg5MDEyMzQ1Ngo=', 
					as_rs_alg: 'A128GCM',
					realm: 'north.gov'});
db.oauth_key.insert({ kid: 'oldempire', 
					ikm_key: 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIK', 
					as_rs_alg: 'A256GCM'});

exit

EOF
