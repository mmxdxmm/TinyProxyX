#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${ANDROID_SDK_ROOT:-/root/android-sdk}"
AJAR="$SDK/platforms/android-34/android.jar"
# 开发树里 app 根是 <root>/src、java 在 <root>/src/src；发行包里 java 直接在 <root>/src
if [ -d "$ROOT/src/com/lcs/tproxy" ]; then SRCROOT="$ROOT/src"; else SRCROOT="$ROOT/src/src"; fi
OUT="$ROOT/test/classes"
rm -rf "$OUT"; mkdir -p "$OUT"
SRC=$(find "$SRCROOT/com/lcs/tproxy/model" "$SRCROOT/com/lcs/tproxy/inject" \
           "$SRCROOT/com/lcs/tproxy/link" "$SRCROOT/com/lcs/tproxy/xray" -name '*.java')
javac -encoding UTF-8 -nowarn -Xlint:-options --release 11 \
  -cp "$AJAR:$ROOT/test/lib/json.jar" -d "$OUT" \
  $SRC $(find "$ROOT/test/stub" "$ROOT/test/src" -name '*.java')
java -cp "$OUT:$ROOT/test/lib/json.jar:$AJAR" com.lcs.tproxy.inject.DumpConfigs /tmp/tpx-configs
