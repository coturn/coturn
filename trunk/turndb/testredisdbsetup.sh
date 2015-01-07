#!/bin/sh

redis-cli <<!

SELECT 2
AUTH turn

set turn/realm/north.gov/user/ninefingers/key "bc807ee29df3c9ffa736523fb2c4e8ee"
set turn/realm/north.gov/user/gorst/key "7da2270ccfa49786e0115366d3a3d14d"

set turn/realm/north.gov/user/bethod/key "3b4125e139811b8577a214c24273fee27b15ff397631c7775b980785a229e6bd"

set turn/realm/crinna.org/user/whirrun/key "6972e85e51f36e53b0b61759c5a5219a"
set turn/realm/crinna.org/user/stranger-come-knocking/key "d43cb678560259a1839bff61c19de15e"

set turn/realm/north.gov/user/ninefingers/password "youhavetoberealistic"
set turn/realm/north.gov/user/gorst/password "hero"

set turn/realm/north.gov/user/bethod/password "king-of-north"

set turn/realm/crinna.org/user/whirrun/password "sword"
set turn/realm/crinna.org/user/stranger-come-knocking/password "civilization"

sadd turn/realm/north.gov/secret "logen" "bloody9"
sadd turn/realm/crinna.org/secret "north" "library"

set turn/user/ninefingers/password "youhavetoberealistic"
set turn/user/gorst/password "hero"

set turn/user/bethod/password "king-of-north"

set turn/user/whirrun/password "sword"
set turn/user/stranger-come-knocking/password "civilization"

set turn/realm/north.gov/admin_user/skarling/password "hoodless"
set turn/admin_user/bayaz/password "magi"

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

hmset turn/oauth/kid/north ikm_key Y2FybGVvbg== hkdf_hash_func 'SHA-256' as_rs_alg 'AES-256-CBC' auth_alg 'HMAC-SHA-256-128'
hmset turn/oauth/kid/oldempire ikm_key YXVsY3Vz hkdf_hash_func 'SHA-256' as_rs_alg 'AEAD-AES-256-GCM'

save

!
