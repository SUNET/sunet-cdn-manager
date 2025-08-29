#!/usr/bin/env bash
set -eu

# Make it so we can run the script from anywhere
cd "$(dirname "$0")"

. settings.sh

cert_dir="certs"
mkdir -p $cert_dir
if ! [ -f $cert_dir/keycloak.key ]; then
    openssl req -x509 -newkey rsa:4096 -days 3650 -noenc -keyout $cert_dir/keycloak.key -out $cert_dir/keycloak.crt -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain"
fi

satosa_frontend_cert_file="../satosa/config/frontend.crt"
if ! [ -f "$satosa_frontend_cert_file" ]; then
    echo "SATOSA not yet initialized ($satosa_frontend_cert_file does not exist): run ../satosa/setup.sh first"
    exit 1
fi
idp_metadata_signing_cert=$(grep -v ' CERTIFICATE-----$' "$satosa_frontend_cert_file" | tr -d '\n')

sed \
    -e "s,%%SIGNING_CERT%%,$idp_metadata_signing_cert," \
    keycloak-satosa-idp.json.in > keycloak-satosa-idp.json

idp_alias=$(jq -r .alias keycloak-satosa-idp.json)

sed \
    -e "s,%%IDP_ALIAS%%,$idp_alias," \
    keycloak-satosa-idp-mapper-first-name.json.in > keycloak-satosa-idp-mapper-first-name.json

sed \
    -e "s,%%IDP_ALIAS%%,$idp_alias," \
    keycloak-satosa-idp-mapper-last-name.json.in > keycloak-satosa-idp-mapper-last-name.json

sed \
    -e "s,%%IDP_ALIAS%%,$idp_alias," \
    keycloak-satosa-idp-mapper-email.json.in > keycloak-satosa-idp-mapper-email.json

sed \
    -e "s,%%IDP_ALIAS%%,$idp_alias," \
    keycloak-satosa-idp-mapper-subject-id.json.in > keycloak-satosa-idp-mapper-subject-id.json

echo "files generated"
