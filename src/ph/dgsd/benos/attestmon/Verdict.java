package ph.dgsd.benos.attestmon;

/**
 * The three states the monitor can report.
 *
 * VALID   - chain verifies to the Google hardware-attestation root, no cert
 *           revoked/expired, and keymasterSecurityLevel == TEE (1). Revocation
 *           data is fresh (refreshed within the staleness window).
 * INVALID - the attestation positively failed: chain doesn't reach the Google
 *           root, a cert is revoked (spoof keybox banned) or expired, or the
 *           security level is not TEE.
 * STALE   - the attestation *looks* valid, but the revocation list could not be
 *           refreshed within the staleness window, so we cannot confirm the
 *           keybox hasn't been banned. Surfaced as a "yellow" warning and
 *           treated as not-to-be-relied-on (fail toward not-valid).
 */
public enum Verdict {
    VALID,
    INVALID,
    STALE
}
