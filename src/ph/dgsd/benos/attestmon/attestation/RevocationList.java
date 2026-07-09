package ph.dgsd.benos.attestmon.attestation;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import ph.dgsd.benos.attestmon.App;
import ph.dgsd.benos.attestmon.R;

/**
 * Certificate revocation status, backed by Google's attestation status list.
 *
 * <p>Adapted from vvb2060/KeyAttestation. Upstream reads a bundled, offline
 * res/raw/status.json. This build keeps the bundled copy only as a cold-start
 * fallback: RevocationFetcher pulls the live list each poll cycle and calls
 * update(), so revocation reflects current Google bans (the signal that a
 * spoofed keybox has been pulled).
 */
public record RevocationList(String status, String reason) {

    // "entries" object of the status list; volatile so the fetcher thread's
    // swap is visible to the checker thread.
    private static volatile JSONObject entries = loadBundled();

    private static JSONObject loadBundled() {
        try (InputStream input = App.app.getResources().openRawResource(R.raw.status)) {
            String text = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            return new JSONObject(text).getJSONObject("entries");
        } catch (IOException | JSONException e) {
            Log.e(App.TAG, "RevocationList: bundled load failed", e);
            return new JSONObject();
        }
    }

    /** Replace the in-memory list with a freshly fetched document ({"entries":{...}}). */
    public static void update(JSONObject raw) throws JSONException {
        entries = raw.getJSONObject("entries");
    }

    public static RevocationList get(BigInteger serialNumber) {
        String serialNumberString = serialNumber.toString(16).toLowerCase();
        JSONObject revocationStatus;
        try {
            revocationStatus = entries.getJSONObject(serialNumberString);
        } catch (JSONException e) {
            return null;
        }
        try {
            String status = revocationStatus.getString("status");
            String reason = revocationStatus.getString("reason");
            return new RevocationList(status, reason);
        } catch (JSONException e) {
            return new RevocationList("", "");
        }
    }

    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
