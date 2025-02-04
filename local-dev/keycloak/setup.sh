#!/usr/bin/env bash

set -eu

# Make it so we can run the script from anywhere
cd "$(dirname "$0")"

base_url="http://localhost:8080"

realm=$(jq -r .realm keycloak-realm.json)
user=$(jq -r .username keycloak-user.json)

# Get access token from username/password
access_token=$(curl -s \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  "$base_url/realms/master/protocol/openid-connect/token" | jq -r .access_token)

# Only do anything if the realm does not exist
realm_response=$(curl -s -X GET \
  -H "Authorization: bearer $access_token" \
  "$base_url/admin/realms/$realm")

if ! echo "$realm_response" | grep -q "Realm not found."; then
    echo "Realm '$realm' alredy exists, doing nothing"
    exit 1
fi

echo "Creating realm '$realm'"
curl -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-realm.json \
  "$base_url/admin/realms"

echo "Creating user '$user'"
# The sed is needed to strip out a \r character present in the header printed by
# curl, without this the content of user_id is not usable in the next step.
user_id=$(curl -si -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-user.json \
  "$base_url/admin/realms/$realm/users" | awk -F/ '/^Location:/{print $NF}' | sed 's/\r$//')

echo "Setting password for user '$user'"
curl -X PUT \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-user-password.json \
  "$base_url/admin/realms/$realm/users/$user_id/reset-password"

echo "Creating oauth2 confidential client for sunet-cdn-manager server"
server_client_id=$(curl -si -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-server-client.json \
  "$base_url/admin/realms/$realm/clients" | awk -F/ '/^Location:/{print $NF}' | sed 's/\r$//')

oidc_server_client_secret=$(curl -s -X GET \
  -H "Authorization: bearer $access_token" \
  "$base_url/admin/realms/$realm/clients/$server_client_id/client-secret" | jq -r .value)

oidc_server_client_id=$(jq -r .clientId keycloak-server-client.json)

echo "Creating oauth2 public client for requesting device grants"
curl -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-device-client.json \
  "$base_url/admin/realms/$realm/clients"

echo
echo "server OIDC client_id: $oidc_server_client_id"
echo "server OIDC client_secret: $oidc_server_client_secret"
