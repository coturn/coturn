#!/bin/sh

# ninefingers:password: youhavetoberealistic
# gorst:password: hero
# whirrun:password: sword
# stranger-come-knocking:password: civilization

redis-cli <<!

SELECT 2
AUTH turn

set turn/realm/north.gov/user/ninefingers/key "bc807ee29df3c9ffa736523fb2c4e8ee"
set turn/realm/north.gov/user/gorst/key "7da2270ccfa49786e0115366d3a3d14d"

set turn/realm/crinna.org/user/whirrun/key "6972e85e51f36e53b0b61759c5a5219a"
set turn/realm/crinna.org/user/stranger-come-knocking/key "d43cb678560259a1839bff61c19de15e"

sadd turn/realm/north.gov/secret "logen" "bloody9"
sadd turn/realm/crinna.org/secret "north" "library"

set turn/realm/north.gov/max-bps 500000
set turn/realm/north.gov/total-quota 12000
set turn/realm/north.gov/user-quota 10000
set turn/realm/crinna.org/max-bps 400000
set turn/realm/crinna.org/total-quota 10000
set turn/realm/crinna.org/user-quota 8000

set turn/origin/http://crinna.org:80 crinna.org
set turn/origin/https://bligh.edu:443 crinna.org

sadd turn/realm/north.gov/allowed-peer-ip "172.17.13.200" "172.17.13.201"
sadd turn/realm/crinna.org/allowed-peer-ip "172.17.13.202"

sadd turn/realm/north.gov/denied-peer-ip "172.17.13.133-172.17.14.56" "172.17.17.133-172.17.19.56" "123::45"
sadd turn/realm/crinna.org/denied-peer-ip "123::77"

hmset turn/oauth/kid/north ikm_key 'Y2FybGVvbg==' hkdf_hash_func 'SHA-256' as_rs_alg 'AES-256-CBC' auth_alg 'HMAC-SHA-256-128'
hmset turn/oauth/kid/oldempire ikm_key 'YXVsY3Vz' hkdf_hash_func 'SHA-256' as_rs_alg 'AEAD-AES-256-GCM'

hmset turn/admin_user/skarling realm 'north.gov' password 'hoodless'
hmset turn/admin_user/bayaz password 'magi'

save

!
