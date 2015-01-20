#!/bin/sh

mongo $* <<EOF

use coturn;

db.turnusers_lt.ensureIndex({ realm: 1, name: 1 }, { unique: 1 });
db.turn_secret.ensureIndex({ realm: 1, value:1 }, { unique: 1 });
db.realm.ensureIndex({ realm: 1 }, { unique: 1 });
db.oauth_key.ensureIndex({ kid: 1 }, {unique: 1 });
db.admin_user.ensureIndex({ name: 1 }, {unique: 1 });

exit

EOF
