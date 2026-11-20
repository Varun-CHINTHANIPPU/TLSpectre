#!/usr/bin/env bash
# Optional external probe tools. No implicit network activity during make test.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p third_party
if [[ ! -d third_party/testssl.sh/.git ]]; then
  git clone --depth 1 https://github.com/testssl/testssl.sh.git third_party/testssl.sh
fi
if [[ ! -d third_party/tlsfuzzer/.git ]]; then
  git clone --depth 1 https://github.com/tlsfuzzer/tlsfuzzer.git third_party/tlsfuzzer
fi
git -C third_party/testssl.sh rev-parse HEAD
git -C third_party/tlsfuzzer rev-parse HEAD
# kyber-py lets tlslite-ng build ML-KEM hybrid key shares for the PR08 enumeration.
python3 -m pip install "tlslite-ng==0.9.0b2" "kyber-py==1.2.0"
echo 'Record these exact SHAs in experiment manifests; unsupported script names remain BLOCKED.'
