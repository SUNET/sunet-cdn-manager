#!/usr/bin/env bash

set -eu

# Make it so we can run the script from anywhere
cd "$(dirname "$0")"

target_dir="config"
plugins_dir="$target_dir/plugins"
metadata_dir="$target_dir/metadata"

if [ -d "$target_dir" ]; then
    echo "directory '$(dirname "$0")/$target_dir' already exists, exiting"
    exit 1
fi

mkdir -p "$target_dir"
mkdir -p "$plugins_dir"

# expected to exist by ../keycloak/setup.sh
mkdir -p "$metadata_dir"

qa_cert_file="$target_dir/swamid-qa.crt"
qa_cert_file_tmp="$qa_cert_file.tmp"

# Setup QA cert
curl -o "$qa_cert_file_tmp" https://mds.swamid.se/qa/md/swamid-qa.crt
# Fingerprint from https://mds.swamid.se/qa/md/
if ! openssl x509 -in $qa_cert_file_tmp -noout -fingerprint -sha256 | grep -q '^sha256 Fingerprint=1E:BC:8E:62:0B:C9:3C:EB:C6:E0:7F:9E:34:B8:A1:9F:EA:A9:30:A1:9E:B5:31:B9:44:8B:0F:CC:3B:D9:17:D2$'; then
    echo "invalid fingerprint in $qa_cert_file_tmp"
    exit 1
fi
mv "$qa_cert_file_tmp" "$qa_cert_file"

state_encryption_key=$(printf '%s\n' "$(LC_ALL=C tr -dc A-Za-z0-9 < /dev/urandom | head -c 32)")
user_id_hash_salt=$(printf '%s\n' "$(LC_ALL=C tr -dc A-Za-z0-9 < /dev/urandom | head -c 32)")

domain="satosa.sunet-cdn.localhost"
base_url="https://$domain:8000"

cp templates/internal_attributes.yaml "$target_dir"

sed \
    -e "s,%%BASE_URL%%,$base_url,g" \
    -e "s,%%STATE_ENCRYPTION_KEY%%,$state_encryption_key,g" \
    -e "s,%%USER_ID_HASH_SALT%%,$user_id_hash_salt,g" \
    templates/proxy_conf.yaml.in > "$target_dir/proxy_conf.yaml"

sed \
    -e "s,%%BASE_URL%%,$base_url,g" \
    templates/saml2_frontend.yaml.in > "$plugins_dir/saml2_frontend.yaml"

sed \
    -e "s,%%BASE_URL%%,$base_url,g" \
    templates/saml2_backend.yaml.in > "$plugins_dir/saml2_backend.yaml"

for cert_name in backend frontend metadata https; do
    if ! [ -f $target_dir/$cert_name.crt ]; then
        echo "generating cert and key for $cert_name"
        # ed25519 - satosa fails to load key
        #openssl req -x509 -newkey ed25519 -days 3650 -noenc -keyout $target_dir/$cert_name.key -out $target_dir/$cert_name.crt -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain"
        # ECDSA - satosa complains about self-signed certificate
        #openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 -noenc -keyout $target_dir/$cert_name.key -out $target_dir/$cert_name.crt -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain"
        # RSA4096
        openssl req -x509 -newkey rsa:4096 -days 3650 -noenc -keyout $target_dir/$cert_name.key -out $target_dir/$cert_name.crt -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain"
    fi
done
