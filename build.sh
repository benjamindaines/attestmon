#!/usr/bin/env bash
# Requires: JDK 17+, Android build-tools 34+ (aapt2, d8, zipalign, apksigner),
# an API 34 android.jar, and the three runtime jars on Maven Central.
set -euo pipefail

# ---- fill these in ----
SDK="/home/ben/Android/Sdk"
BT="$SDK/build-tools/35.0.0"                 # build-tools 34 bugs out, 35 works
ANDROID_JAR="$SDK/platforms/android-34/android.jar"
PLATFORM_PK8=""              
PLATFORM_PEM=""             
DEPS="libs"                

# Build-deps:
#   bcprov-jdk18on-1.80.jar    (org.bouncycastle:bcprov-jdk18on:1.80)
#   guava-33.4.0-android.jar   (com.google.guava:guava:33.4.0-android)
#   cbor-0.9.jar               (co.nstant.in:cbor:0.9)
# (cbor is only needed if the device ever emits EAT/.25 attestation)

rm -rf build && mkdir -p build/compiled build/gen build/classes build/dex
CP="$ANDROID_JAR:$DEPS/*"

echo "[1/6] aapt2 compile resources"
"$BT/aapt2" compile --dir res -o build/compiled/res.zip

echo "[2/6] aapt2 link -> gen R.java + resources.apk"
"$BT/aapt2" link \
  -o build/resources.apk \
  --manifest AndroidManifest.xml \
  -I "$ANDROID_JAR" \
  --min-sdk-version 34 --target-sdk-version 34 \
  --java build/gen \
  build/compiled/res.zip

echo "[3/6] javac"
find src build/gen -name '*.java' > build/sources.txt
javac -source 17 -target 17 -encoding UTF-8 -nowarn \
  -classpath "$CP" -d build/classes @build/sources.txt

echo "[4/6] d8 (app classes + deps -> classes.dex, records/text-blocks desugared)"
"$BT/d8" --release --min-api 34 --lib "$ANDROID_JAR" \
  --output build/dex \
  $(find build/classes -name '*.class') "$DEPS"/*.jar

echo "[5/6] assemble + zipalign"
cp build/resources.apk build/attestmon.unsigned.apk
( cd build/dex && zip -q ../attestmon.unsigned.apk classes.dex )
"$BT/zipalign" -f 4 build/attestmon.unsigned.apk build/attestmon.aligned.apk

echo "[6/6] apksigner (platform key)"
"$BT/apksigner" sign \
  --key "$PLATFORM_PK8" --cert "$PLATFORM_PEM" \
  --out build/attestmon.apk build/attestmon.aligned.apk
"$BT/apksigner" verify --verbose build/attestmon.apk

echo "done -> build/attestmon.apk"
