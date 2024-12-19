#!/bin/bash
set -e

# Create database named after user, then create a schema named the same as the
# user which is also owned by that user. Because search_path (SHOW
# search_path;) starts with "$user" by default this means any tables will be
# created in that user-specific SCHEMA by default instead of falling back to
# "public". This follows the "secure schema usage pattern" summarized as
# "Constrain ordinary users to user-private schemas" from
# https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATTERNS
#
# "In PostgreSQL 15 and later, the default configuration supports this usage
# pattern. In prior versions, or when using a database that has been upgraded
# from a prior version, you will need to remove the public CREATE privilege
# from the public schema"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE USER cdn WITH PASSWORD 'cdn';
	CREATE DATABASE cdn;
	GRANT ALL PRIVILEGES ON DATABASE cdn TO cdn;
	CREATE USER keycloak WITH PASSWORD 'keycloak';
	CREATE DATABASE keycloak;
	GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
	\c cdn;
	CREATE SCHEMA cdn AUTHORIZATION cdn;
	\c keycloak;
	CREATE SCHEMA keycloak AUTHORIZATION keycloak;
EOSQL
