#!/bin/sh

# ninefingers:password: youhavetoberealistic
# gorst:password: hero
# whirrun:password: sword
# stranger-come-knocking:password: civilization
#
# bayaz admin user password: magi
# skarling admin user password: hoodless

redis-cli <<!

AUTH turn
SELECT 2

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

hmset turn/oauth/kid/north ikm_key 'MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEK' as_rs_alg 'A256GCM' realm 'crinna.org'
hmset turn/oauth/kid/union ikm_key 'MTIzNDU2Nzg5MDEyMzQ1Ngo=' as_rs_alg 'A128GCM' realm 'north.gov'
hmset turn/oauth/kid/oldempire ikm_key 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIK' as_rs_alg 'A256GCM'

hmset turn/admin_user/skarling realm 'north.gov' password '\$5\$6fc35c3b0c7d4633\$27fca7574f9b79d0cb93ae03e45379470cbbdfcacdd6401f97ebc620f31f54f2'
hmset turn/admin_user/bayaz password '\$5\$e018513e9de69e73\$5cbdd2e29e04ca46aeb022268a7460d3a3468de193dcb2b95f064901769f455f'

save

!
