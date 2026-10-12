#!/bin/sh
set -eu

EXPECTED_SHA256="A61ADEAB895EF5A4DB436E0A7011C92A2FF17BB0357F58B13BBC4062E535E7B9"
MICROSOFT_URL="https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26200.6584.250915-1905.25h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUTPUT_ISO" >&2
    exit 2
fi

output="$1"
partial="${output}.partial"
if [ -e "$output" ] || [ -e "$partial" ]; then
    echo "Refusing to overwrite existing output or partial file" >&2
    exit 3
fi

mkdir -p "$(dirname "$output")"
curl --fail --location --proto '=https' --tlsv1.2 \
    --retry 5 --retry-all-errors \
    --output "$partial" "$MICROSOFT_URL"

actual="$(sha256sum "$partial" | awk '{print toupper($1)}')"
if [ "$actual" != "$EXPECTED_SHA256" ]; then
    echo "Downloaded ISO SHA-256 mismatch: expected $EXPECTED_SHA256, got $actual" >&2
    exit 4
fi

mv "$partial" "$output"
printf '%s  %s\n' "$EXPECTED_SHA256" "$(basename "$output")" >"${output}.sha256"
