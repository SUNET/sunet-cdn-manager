#!/usr/bin/env bash

set -eu

# Make it so we can run the script from anywhere
cd "$(dirname "$0")"

gen_dir="generated"
target_dir="$gen_dir/manager"
cert_dir="$target_dir/certs"

mkdir -p "$target_dir"
mkdir -p "$cert_dir"

domain="manager.sunet-cdn.localhost"
cert_name="$domain"

if ! [ -f "$cert_dir/$cert_name.crt" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 -noenc -keyout $cert_dir/$cert_name.key -out $cert_dir/$cert_name.crt -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain"
fi

echo "files generated under $(dirname "$0")/$gen_dir"
