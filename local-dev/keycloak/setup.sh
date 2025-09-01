#!/usr/bin/env bash

set -eu

# Make it so we can run the script from anywhere
cd "$(dirname "$0")"

. settings.sh

gen_dir="generated"

base_url="https://$domain:8443"

realm=$(jq -r .realm keycloak-realm.json)
user=$(jq -r .username keycloak-user.json)
idp_alias=$(jq -r .alias "$gen_dir/keycloak-satosa-idp.json")

# Get access token from username/password
access_token=$(curl -ks \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  "$base_url/realms/master/protocol/openid-connect/token" | jq -r .access_token)

# Only do anything if the realm does not exist
realm_response=$(curl -ks -X GET \
  -H "Authorization: bearer $access_token" \
  "$base_url/admin/realms/$realm")

if ! echo "$realm_response" | grep -q "Realm not found."; then
    echo "Realm '$realm' alredy exists, doing nothing"
    exit 1
fi

echo "Creating realm '$realm'"
curl -k -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-realm.json \
  "$base_url/admin/realms"

echo "Creating identity provider"
curl -ksi -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d "@$gen_dir/keycloak-satosa-idp.json" \
  "$base_url/admin/realms/$realm/identity-provider/instances"

# We need to create attribute mappers for email, first name and last name for
# Keycloak to fill these in when creating users based on logins.
# A side effect of creating such mappers is that they are also added to the
# generated SAML metadata e.g.:
# ===
# <md:AttributeConsumingService index="0" isDefault="true">
#   <md:ServiceName xml:lang="en">sunet-cdn-manager</md:ServiceName>
#   <md:RequestedAttribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
#   <md:RequestedAttribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
#   <md:RequestedAttribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
# </md:AttributeConsumingService>
# ===
# ... and by default SATOSA will automatically filter out attributes that are
# not part of this list. Importantly it means it will filter out the configured
# "Principal attribute" subject-id which stops logins from working with an error like:
# ===
# 2025-08-29 21:23:16,670 ERROR [org.keycloak.broker.saml.SAMLEndpoint] (executor-thread-5) no principal in assertion; expected: ATTRIBUTE(urn:oasis:names:tc:SAML:attribute:subject-id)
# ===
# Another thing I noticed is that if you omit the "Attribute Name" and only set
# the "Friendly name" this is enough for keycloak to fill things in, but then
# the Name field is missing in the metadata, and this breaks SATOSA making it print
# stack traces ending with:
# ===
#    File "/usr/local/lib/python3.9/site-packages/saml2/assertion.py", line 87, in _match_attr_name
#      name = attr["name"].lower()
#  KeyError: 'name'
# ===
# ... so fill in the "Attribute Name" field with the OID as well. Even if the
# AttributeConsumingService is now stripped with xmlstarlet below lets keep
# making sure the unstripped metadata is valid for SATOSA in case we want to
# use it like that in the future.
echo "Creating first name mapper"
curl -ksi -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d "@$gen_dir/keycloak-satosa-idp-mapper-first-name.json" \
  "$base_url/admin/realms/$realm/identity-provider/instances/$idp_alias/mappers"

echo "Creating last name mapper"
curl -ksi -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d "@$gen_dir/keycloak-satosa-idp-mapper-last-name.json" \
  "$base_url/admin/realms/$realm/identity-provider/instances/$idp_alias/mappers"

echo "Creating email mapper"
curl -ksi -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d "@$gen_dir/keycloak-satosa-idp-mapper-email.json" \
  "$base_url/admin/realms/$realm/identity-provider/instances/$idp_alias/mappers"

# Make metadata available to SATOSA
#
# Use xmlstarlet to strip out the AttributeConsumingService added by the
# mappers created above so we do not need to care about updating these. As
# "what attributes the application will get" is controlled by the
# entity-category applied to the SATOSA metadata in SWAMID having a second
# place to limit these via SATOSA just seems confusing.
curl -ks "$base_url/realms/$realm/broker/$idp_alias/endpoint/descriptor" | xmlstarlet ed -d '/md:EntityDescriptor/md:SPSSODescriptor/md:AttributeConsumingService' > "../satosa/$gen_dir/config/metadata/keycloak_sp_metadata.xml"

echo "Creating user '$user'"
# The sed is needed to strip out a \r character present in the header printed by
# curl, without this the content of user_id is not usable in the next step.
user_id=$(curl -ksi -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-user.json \
  "$base_url/admin/realms/$realm/users" | awk -F/ '/^(L|l)ocation:/{print $NF}' | sed 's/\r$//')

echo "Setting password for user '$user'"
curl -k -X PUT \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-user-password.json \
  "$base_url/admin/realms/$realm/users/$user_id/reset-password"


echo "Creating oauth2 confidential client for sunet-cdn-manager server"
server_client_id=$(curl -ksi -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-server-client.json \
  "$base_url/admin/realms/$realm/clients" | awk -F/ '/^(L|l)ocation:/{print $NF}' | sed 's/\r$//')

oidc_server_client_secret=$(curl -ks -X GET \
  -H "Authorization: bearer $access_token" \
  "$base_url/admin/realms/$realm/clients/$server_client_id/client-secret" | jq -r .value)

oidc_server_client_id=$(jq -r .clientId keycloak-server-client.json)

echo "Creating oauth2 public client for requesting device grants"
curl -k -X POST \
  -H "Authorization: bearer $access_token" \
  -H "Content-Type: application/json" \
  -d @keycloak-device-client.json \
  "$base_url/admin/realms/$realm/clients"

echo
echo "server OIDC client_id: $oidc_server_client_id"
echo "server OIDC client_secret: $oidc_server_client_secret"
