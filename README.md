# BenOS Attestation Monitor

Headless, platform-signed system app for the Zinwa Q25 (Helio G99, Android 14 /
API 34). Every 30 minutes it generates a fresh TEE-attested EC key, checks
whether the attestation chain still verifies to the Google hardware-attestation
root, and notifies you when the verdict changes. Read-only status monitor: it
does not create, install, or manage the keybox spoof and does not touch Play
Integrity.

## Verdicts

- **VALID** — chain reaches the Google root, no cert revoked/expired, keymaster
  security level == TEE, and the revocation list refreshed within 3 days.
- **INVALID** — chain positively failed (no Google root, a cert revoked — i.e.
  keybox banned — or expired, or not TEE-backed).
- **STALE** (yellow) — chain looks valid but the revocation list could not be
  refreshed for >3 days, so a ban can't be ruled out. Treated as not-valid.

Revocation is pulled live each cycle from Google's attestation status list, with
the last successful response cached on disk (bundled `res/raw/status.json` is the
cold-start fallback). Failure to refresh keeps the last-good list until it goes
stale, then flips to STALE. Fails toward not-valid by design.

Alerts are `IMPORTANCE_HIGH` but silent (no sound/vibration). A change occurring
while the screen is off/locked is held and shown as a heads-up on next unlock;
if several changes queue while locked, only the most recent is shown, and nothing
is shown if the net state matches what you last saw.

## Build

Raw toolchain, no Gradle. Edit the paths at the top of `build.sh`, drop the three
jars into `libs/`, then:

    ./build.sh        # -> build/attestmon.apk

Deps (Maven Central): `bcprov-jdk18on:1.80`, `guava:33.4.0-android`, `cbor:0.9`.
Needs JDK 17+ and build-tools 34+ (record/text-block desugaring). If the device
never emits EAT (`.25`) attestation you can drop `cbor:0.9` and the
`EatAttestation`/`EatClaim`/`CborUtils` files.

## Provenance

The `attestation/` package is lifted from vvb2060/KeyAttestation (Apache-2.0 /
AOSP) with two edits only: package rename to `ph.dgsd.benos.attestmon.attestation`,
and `RevocationList` rewired to a live-refreshable cache instead of the offline
bundled list. The AIDL / `ActivityThread` reflection / Shizuku root-shell path was
intentionally not lifted — as a platform-signed system app the standard
`AndroidKeyStore` provider is used in-process.
