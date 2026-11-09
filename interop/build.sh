#!/bin/sh
# Builds the Go interop harness against a pristine copy of upstream Ironwood,
# with petrified's export files added. Usage: build.sh OUTPUT_DIR
set -eu
out="$1"
here="$(cd "$(dirname "$0")" && pwd)"
go="${GO:-go}"
cd "$here/harness"
"$go" mod download github.com/Arceliar/ironwood
src="$("$go" list -m -f '{{.Dir}}' github.com/Arceliar/ironwood)"
rm -rf "$out"
mkdir -p "$out"
cp -R "$src" "$out/ironwood"
chmod -R u+w "$out/ironwood"
cp "$here/inject/network/"*.go "$out/ironwood/network/"
cp "$here/inject/encrypted/"*.go "$out/ironwood/encrypted/"
cp -R "$here/harness" "$out/harness"
cd "$out/harness"
"$go" mod edit -replace "github.com/Arceliar/ironwood=$out/ironwood"
"$go" build -o "$out/harness-bin" .
