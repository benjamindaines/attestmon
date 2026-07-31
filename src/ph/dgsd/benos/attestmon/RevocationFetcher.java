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
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;

import ph.dgsd.benos.attestmon.attestation.RevocationList;

/**
 * Pulls Google's attestation status list each cycle and feeds it to
 * {@link RevocationList}. Keeps the last successful response on disk so a
 * transient network failure doesn't lose the current list; the staleness of
 * that cache (tracked via {@link Prefs}) is what drives the STALE verdict.
 *
 * <p>Two fetch modes:
 *   -refresh: conditional. Echoes the stored ETag / Last-Modified
 *       validators. 304 = unchanged, keep current cache as valid. 200 = save new list,
 *	wipe current cache with new.
 *  -forceRefresh: cache-bypassing. Force-pull new, current list. Clobber
 *   current cache. If cannot refresh, keep current cache, but maintain stale state.
 *
 * <p>Prior behaviour treated any non-200 code (including 304) as a failure, so an
 * unchanged list neither advanced last-good nor touched the cache; after the
 * staleness window elapsed the verdict flipped to STALE despite a valid cache.
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

    // Conditional refresh
    // Status 304 (unchanged) keep cached cache valid
    // Status 200 wipes and re-downloads cache

    public boolean refresh(Context ctx, Prefs prefs) {
        return doRefresh(ctx, prefs, false);
    }


    public boolean forceRefresh(Context ctx, Prefs prefs) {
        return doRefresh(ctx, prefs, true);
    }

    private boolean doRefresh(Context ctx, Prefs prefs, boolean force) {
        File cacheFile = new File(ctx.getFilesDir(), CACHE_FILE);
        boolean cachePresent = cacheFile.exists();
        HttpURLConnection conn = null;
        try {
            // When cache is legitimately stale, force refresh as new session to avoid
	    // dealing with return status codes.
            String spec = force ? STATUS_URL + "?_=" + System.currentTimeMillis() : STATUS_URL;
            conn = (HttpURLConnection) new URL(spec).openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/json");

            if (force) {
                conn.setUseCaches(false);
                conn.setRequestProperty("Cache-Control", "no-cache");
                conn.setRequestProperty("Pragma", "no-cache");
            } else {
                // Conditional fetch: echo validators so an unchanged list yields a
                // cheap 304. Only sent when a cache exists to validate against.
                if (cachePresent) {
                    String etag = prefs.etag();
                    String lastMod = prefs.lastModified();
                    if (etag != null) conn.setRequestProperty("If-None-Match", etag);
                    if (lastMod != null) conn.setRequestProperty("If-Modified-Since", lastMod);
                }
            }

            int code = conn.getResponseCode();

            if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
                // 304: the server confirms the cached list is current. Treat as a
                // successful refresh 
                if (!cachePresent) {
                    Log.w(App.TAG, "revocation: 304 with no cache on disk; treating as failure");
                    return false;
                }
                touchCacheMtime(cacheFile);
                prefs.setLastGoodNow();
                Log.i(App.TAG, "revocation: 304 not-modified; cache revalidated");
                return true;
            }

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
            Files.write(cacheFile.toPath(), body.getBytes(StandardCharsets.UTF_8));
            // Persist validators for the next conditional request. Absent headers
            // clear the stored values so a later request doesn't send stale ones.
            prefs.setValidators(conn.getHeaderField("ETag"), conn.getHeaderField("Last-Modified"));
            prefs.setLastGoodNow();
            Log.i(App.TAG, "revocation: live refresh ok" + (force ? " (forced)" : ""));
            return true;
        } catch (Throwable t) {
            Log.w(App.TAG, "revocation: refresh failed (" + t.getClass().getSimpleName() + ")");
            return false;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * Advance the cache file's last-modified time to now. Freshness itself is
     * tracked in Prefs; this keeps the on-disk metadata consistent with the
     * revalidation for external inspection. .
     */
    private static void touchCacheMtime(File cacheFile) {
        try {
            Path p = cacheFile.toPath();
            Files.setLastModifiedTime(p, FileTime.fromMillis(System.currentTimeMillis()));
        } catch (Throwable t) {
            Log.w(App.TAG, "revocation: cache mtime touch failed (" + t.getClass().getSimpleName() + ")");
        }
    }
}
