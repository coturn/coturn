### init db with coturn schema
FROM mariadb

ADD init-coturn-db.sql /docker-entrypoint-initdb.d

ADD schema.sql /docker-entrypoint-initdb.d
