#!/usr/bin/env bash
set -uo pipefail
for command in 'java -version' 'python3 --version' 'mvn -v' 'openssl version -a' 'nginx -v' 'tshark --version' 'curl -V'; do
  echo "=== $command ==="
  bash -c "$command" 2>&1 | head -n 12 || true
done
for tool in testssl.sh tlsfuzzer; do
  echo "=== $tool git sha ==="
  git -C "third_party/$tool" rev-parse HEAD 2>/dev/null || true
done
uname -a
cat /etc/os-release
