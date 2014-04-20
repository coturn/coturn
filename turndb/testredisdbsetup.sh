#!/bin/sh

redis-cli <<!

SELECT 2
AUTH turn

set turn/realm/north.gov/user/ninefingers/key "bc807ee29df3c9ffa736523fb2c4e8ee"
set turn/realm/north.gov/user/gorst/key "7da2270ccfa49786e0115366d3a3d14d"
set turn/realm/crinna.org/user/whirrun/key "6972e85e51f36e53b0b61759c5a5219a"
set turn/realm/crinna.org/user/stranger-come-knocking/key "d43cb678560259a1839bff61c19de15e"

set turn/realm/north.gov/user/ninefingers/password "youhavetoberealistic"
set turn/realm/north.gov/user/gorst/password "hero"
set turn/realm/crinna.org/user/whirrun/password "sword"
set turn/realm/crinna.org/user/stranger-come-knocking/password "civilization"

set turn/realm/north.gov/secret/1368426581 "logen"
set turn/realm/crinna.org/secret/777888999 "north"

set turn/user/ninefingers/password "youhavetoberealistic"
set turn/user/gorst/password "hero"
set turn/user/whirrun/password "sword"
set turn/user/stranger-come-knocking/password "civilization"

set turn/realm/north.gov/max-bps 500000
set turn/realm/north.gov/total-quota 12000
set turn/realm/north.gov/user-quota 10000
set turn/realm/crinna.org/max-bps 400000
set turn/realm/crinna.org/total-quota 10000
set turn/realm/crinna.org/user-quota 8000

set turn/origin/http://crinna.org:80 crinna.org
set turn/origin/https://bligh.edu:443 crinna.org

set turn/denied-peer-ip/123456 "172.17.13.133-172.17.14.56"
set turn/denied-peer-ip/234567 "123::45"

set turn/allowed-peer-ip/345678 "172.17.13.200"

save

!
