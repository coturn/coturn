#!/bin/sh

mongo $* <<EOF

use turn;

db.turnusers_lt.ensureIndex({ realm: 1, name: 1 }, { unique: 1 });
db.turnusers_st.ensureIndex({ name: 1 }, { unique: 1 });
db.turn_secret.ensureIndex({ realm: 1 }, { unique: 1 });
db.realm.ensureIndex({ realm: 1 }, { unique: 1 });

exit

EOF
