#!/bin/sh
# Runs once, on first PostgreSQL init (empty data volume), via the postgres
# image's /docker-entrypoint-initdb.d mechanism.
#
# Creates a dedicated `pdns` database for PowerDNS (separate from the app's
# `postgres` database) and loads the upstream gpgsql schema into it. The schema
# file is mounted at /schemas/ rather than in the init dir so postgres does not
# auto-run it against the wrong database.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOSQL
CREATE DATABASE pdns;
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname pdns \
    -f /schemas/pdns-schema.pgsql.sql

echo "PowerDNS schema loaded into 'pdns' database."
