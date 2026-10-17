#!/usr/bin/env bash
# build mimic: compile + fat jar. No third-party deps; requires JDK 21.
set -euo pipefail
cd "$(dirname "$0")"

command -v javac >/dev/null 2>&1 || { echo "javac not found — install a JDK 21" >&2; exit 1; }

rm -rf build dist
mkdir -p build dist

javac -encoding UTF-8 -d build src/mimic/*.java
jar --create --file dist/mimic.jar --main-class mimic.Main -C build .

echo "dist/mimic.jar"
