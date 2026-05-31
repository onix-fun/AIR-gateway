#!/bin/sh
set -eu

private_key=$1

base64url() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

header=$(printf '{"alg":"RS256","typ":"JWT"}' | base64url)
payload=$(printf '{"iss":"account-service","aud":"sparrow","sub":"gateway-test","exp":4102444800}' | base64url)
unsigned_token="$header.$payload"
signature=$(printf '%s' "$unsigned_token" | openssl dgst -sha256 -sign "$private_key" | base64url)

printf '%s.%s\n' "$unsigned_token" "$signature"
