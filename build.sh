#!/usr/bin/env bash
# TinyProxy X - hand rolled build (aapt2 + javac + d8 + zipalign + apksigner)
# Linux 等价于 build.ps1
set -euo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK="${ANDROID_SDK_ROOT:-/root/android-sdk}"
BT="$SDK/build-tools/34.0.0"
ANDROID_JAR="$SDK/platforms/android-34/android.jar"
STAGE="${TPX_STAGE:-$PROJ/.stage}"
BUILD="$STAGE/build"
OUT="$PROJ/build"

AAPT2="$BT/aapt2"
D8="$BT/d8"
ZIPALIGN="$BT/zipalign"
APKSIGNER="$BT/apksigner"
# 签名证书：优先用包内自带的，没有就用上一级目录的，再没有就现生成一个（和 build.ps1 一致）
KS="$PROJ/sign/signing/tpx-debug.keystore"
[ -e "$KS" ] || KS="$(dirname "$PROJ")/tpx-debug.keystore"
[ -e "$KS" ] || KS="$PROJ/build/tpx-debug.keystore"

for f in "$AAPT2" "$D8" "$ZIPALIGN" "$APKSIGNER" "$ANDROID_JAR"; do
  [ -e "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

if [ ! -e "$KS" ]; then
  echo "== generating keystore -> $KS"
  mkdir -p "$(dirname "$KS")"
  keytool -genkeypair -keystore "$KS" -storetype PKCS12 -storepass android -keypass android \
    -alias tinyproxy -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=TinyProxy X, OU=dev, O=lcs, L=CN, ST=CN, C=CN"
fi

VER="$(sed -n 's/.*versionName="\([^"]*\)".*/\1/p' "$PROJ/AndroidManifest.xml" | head -1)"
VCODE="$(sed -n 's/.*versionCode="\([0-9]*\)".*/\1/p' "$PROJ/AndroidManifest.xml" | head -1)"
echo "== TinyProxyX $VER (code $VCODE)"

echo "== stage -> $STAGE"
rm -rf "$STAGE"
mkdir -p "$BUILD/classes" "$BUILD/dex"
cp -r "$PROJ/res" "$PROJ/src" "$PROJ/assets" "$PROJ/jniLibs" "$STAGE/"
cp "$PROJ/AndroidManifest.xml" "$STAGE/"

echo "== aapt2 compile"
"$AAPT2" compile --dir "$STAGE/res" -o "$BUILD/res.zip"

echo "== aapt2 link"
"$AAPT2" link -o "$BUILD/base.apk" -I "$ANDROID_JAR" \
  --manifest "$STAGE/AndroidManifest.xml" \
  -R "$BUILD/res.zip" -A "$STAGE/assets" \
  --min-sdk-version 26 --target-sdk-version 34 \
  --version-code "$VCODE" --version-name "$VER" --auto-add-overlay

echo "== javac"
mapfile -t SRCS < <(find "$STAGE/src" -name '*.java')
echo "   sources: ${#SRCS[@]}"
javac --release 11 -encoding UTF-8 -nowarn -Xlint:-options \
  -classpath "$ANDROID_JAR" -d "$BUILD/classes" "${SRCS[@]}"

echo "== d8"
( cd "$BUILD/classes" && jar -cf "$BUILD/classes.jar" . )
"$D8" --min-api 26 --lib "$ANDROID_JAR" --output "$BUILD/dex" "$BUILD/classes.jar"
[ -f "$BUILD/dex/classes.dex" ] || { echo "no classes.dex" >&2; exit 1; }

echo "== package"
python3 "$PROJ/tools/zipadd.py" "$BUILD/base.apk" "$BUILD/dex/classes.dex" "$STAGE/jniLibs" "$BUILD/packed.apk"

echo "== zipalign"
"$ZIPALIGN" -f -p 4 "$BUILD/packed.apk" "$BUILD/aligned.apk"

echo "== sign"
mkdir -p "$OUT"
FINAL="$OUT/TinyProxyX-$VER.apk"
rm -f "$FINAL"
"$APKSIGNER" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --ks-key-alias tinyproxy --out "$FINAL" "$BUILD/aligned.apk"
"$APKSIGNER" verify --print-certs "$FINAL" | head -5

echo
echo "BUILD OK: $FINAL"
du -h "$FINAL"
