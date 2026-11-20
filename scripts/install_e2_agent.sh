#!/usr/bin/env bash
# Install the exact published Maven Central artifact required for E2.
# Does not run the agent, and never commits or uploads extracted TLS secrets.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p third_party

VERSION="5.0.0"
DEST="third_party/extract-tls-secrets-${VERSION}.jar"
if [[ ! -s "$DEST" ]]; then
  mvn -f java/pom.xml -B -ntp org.apache.maven.plugins:maven-dependency-plugin:3.9.0:copy \
    -Dartifact="name.neykov:extract-tls-secrets:${VERSION}:jar" \
    -DoutputDirectory="$PWD/third_party" \
    -Dmdep.stripVersion=false
fi

if [[ ! -s "$DEST" ]]; then
  echo "E2 agent download did not create $DEST" >&2
  exit 1
fi

# Require a Java-agent Premain-Class, not simply a similarly named JAR.
python3 - "$DEST" <<'PY'
import sys
from zipfile import ZipFile, BadZipFile
try:
    with ZipFile(sys.argv[1]) as archive:
        manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8")
    assert any(line.startswith("Premain-Class:") for line in manifest.splitlines())
except (BadZipFile, KeyError, AssertionError, UnicodeError) as exc:
    raise SystemExit(f"Not a valid startup javaagent: {exc}")
PY

# Preserve exact artifact SHA-256 for the run manifest and future pinning.
sha256sum "$DEST" | tee "third_party/extract-tls-secrets-${VERSION}.jar.sha256"
echo "Installed Maven Central name.neykov:extract-tls-secrets:${VERSION} into $DEST"
echo "Record this SHA-256 in experiment provenance before publication."
