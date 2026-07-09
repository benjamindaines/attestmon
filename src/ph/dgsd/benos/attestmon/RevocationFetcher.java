package ph.dgsd.benos.attestmon;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import ph.dgsd.benos.attestmon.attestation.RevocationList;

/**
 * Pulls Google's attestation status list each cycle and feeds it to
 * {@link RevocationList}. Keeps the last successful response on disk so a
 * transient network failure doesn't lose the current list; the staleness of
 * that cache (tracked via {@link Prefs}) is what drives the STALE verdict.
 */
public final class RevocationFetcher {
    private static final String STATUS_URL =
            "https://android.googleapis.com/attestation/status";
    private static final String CACHE_FILE = "status_cache.json";
    private static final int TIMEOUT_MS = 15_000;

    /** Load the on-disk cache (if any) into RevocationList at cold start. */
    public static void loadCacheIfPresent(Context ctx) {
        File f = new File(ctx.getFilesDir(), CACHE_FILE);
        if (!f.exists()) return;
        try {
            String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            RevocationList.update(new JSONObject(text));
            Log.i(App.TAG, "revocation: loaded cached status list");
        } catch (Throwable t) {
            Log.w(App.TAG, "revocation: cache load failed", t);
        }
    }

    /**
     * Fetch the live list. On success: swap it into RevocationList, persist the
     * cache, stamp last-good, return true. On any failure: leave the current
     * list/cache untouched and return false.
     */
    public boolean refresh(Context ctx, Prefs prefs) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(STATUS_URL).openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/json");
            int code = conn.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                Log.w(App.TAG, "revocation: HTTP " + code);
                return false;
            }
            String body;
            try (InputStream in = conn.getInputStream()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            JSONObject json = new JSONObject(body); // throws if malformed -> failure
            RevocationList.update(json);            // validates it has "entries"
            Files.write(new File(ctx.getFilesDir(), CACHE_FILE).toPath(),
                    body.getBytes(StandardCharsets.UTF_8));
            prefs.setLastGoodNow();
            Log.i(App.TAG, "revocation: live refresh ok");
            return true;
        } catch (Throwable t) {
            Log.w(App.TAG, "revocation: refresh failed (" + t.getClass().getSimpleName() + ")");
            return false;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}
