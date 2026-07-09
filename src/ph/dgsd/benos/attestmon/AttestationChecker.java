package ph.dgsd.benos.attestmon;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

import ph.dgsd.benos.attestmon.attestation.Attestation;
import ph.dgsd.benos.attestmon.attestation.CertificateInfo;
import ph.dgsd.benos.attestmon.attestation.RootPublicKey;

/**
 * Generates a fresh attested EC key each cycle and evaluates the resulting
 * certificate chain. "Valid" == chains to the Google hardware-attestation root,
 * every cert healthy (signature verifies, not revoked per the live status list,
 * not expired), and keymasterSecurityLevel == TEE. Key is deleted before and
 * after so the keystore stays clean and the spoof path is exercised live.
 *
 * This is spoof-agnostic: it evaluates the attestation exactly as presented.
 * No StrongBox (G99 is TEE-only; requesting it would fail key generation).
 */
public final class AttestationChecker {
    private static final String ALIAS = "attestmon_probe";

    public static final class ChainResult {
        public final boolean valid;
        public final String detail;
        ChainResult(boolean valid, String detail) { this.valid = valid; this.detail = detail; }
    }

    public ChainResult evaluateChain() {
        deleteAlias(); // guard against a key left by a killed cycle
        try {
            generate();
            Certificate[] chain = loadChain();
            if (chain == null || chain.length == 0) {
                return new ChainResult(false, "no certificate chain");
            }
            List<X509Certificate> certs = new ArrayList<>(chain.length);
            for (Certificate c : chain) certs.add((X509Certificate) c);

            List<CertificateInfo> infos = new ArrayList<>();
            CertificateInfo.parse(certs, infos); // parse() orders root -> leaf

            RootPublicKey.Status issuer = infos.get(0).getIssuer();
            boolean googleRoot = issuer == RootPublicKey.Status.GOOGLE;

            boolean allNormal = true;
            for (CertificateInfo ci : infos) {
                if (ci.getStatus() != CertificateInfo.CERT_NORMAL) { allNormal = false; break; }
            }

            Attestation att = null;
            for (CertificateInfo ci : infos) {
                if (ci.getAttestation() != null) att = ci.getAttestation();
            }
            boolean tee = att != null
                    && att.getKeymasterSecurityLevel() == Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;

            boolean valid = googleRoot && allNormal && tee;
            String detail = "root=" + issuer
                    + " chainHealthy=" + allNormal
                    + " level=" + (att == null ? "none"
                        : Attestation.securityLevelToString(att.getKeymasterSecurityLevel()));
            return new ChainResult(valid, detail);
        } catch (Throwable t) {
            Log.e(App.TAG, "evaluateChain failed", t);
            return new ChainResult(false, "error: " + t.getClass().getSimpleName()
                    + " " + String.valueOf(t.getMessage()));
        } finally {
            deleteAlias();
        }
    }

    private void generate() throws Exception {
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge); // value irrelevant for a self-check; hygiene
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(spec);
        kpg.generateKeyPair();
    }

    private Certificate[] loadChain() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks.getCertificateChain(ALIAS);
    }

    private void deleteAlias() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
        } catch (Throwable ignored) { }
    }
}
