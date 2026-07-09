package ph.dgsd.benos.attestmon;

import android.content.Context;
import android.content.SharedPreferences;

/** Thin wrapper over SharedPreferences for the monitor's persisted state. */
public final class Prefs {
    private static final String FILE = "attestmon";
    private static final String K_FIRST_RUN   = "first_run";     // epoch ms, set once
    private static final String K_LAST_GOOD    = "last_good";     // epoch ms of last successful revocation refresh
    private static final String K_LAST_SEEN    = "last_seen";     // Verdict the user last actually saw
    private static final String K_PENDING      = "pending";       // Verdict held while locked (or null)
    private static final String K_INITIALIZED  = "initialized";   // first check recorded without notifying

    private final SharedPreferences sp;

    public Prefs(Context ctx) {
        sp = ctx.getApplicationContext().getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    /** First-run timestamp; lazily initialised. Doubles as the freshness clock origin. */
    public long firstRun() {
        long v = sp.getLong(K_FIRST_RUN, 0L);
        if (v == 0L) {
            v = System.currentTimeMillis();
            sp.edit().putLong(K_FIRST_RUN, v).apply();
        }
        return v;
    }

    /** Timestamp of the last successful live revocation-list refresh (0 if never). */
    public long lastGood() { return sp.getLong(K_LAST_GOOD, 0L); }
    public void setLastGoodNow() { sp.edit().putLong(K_LAST_GOOD, System.currentTimeMillis()).apply(); }

    /**
     * Effective freshness origin: last successful refresh, or first-run time if we
     * have never refreshed (gives a grace window on the bundled snapshot).
     */
    public long freshnessOrigin() {
        long lg = lastGood();
        return lg != 0L ? lg : firstRun();
    }

    public boolean initialized() { return sp.getBoolean(K_INITIALIZED, false); }
    public void setInitialized() { sp.edit().putBoolean(K_INITIALIZED, true).apply(); }

    public Verdict lastSeen() {
        String s = sp.getString(K_LAST_SEEN, null);
        return s == null ? null : Verdict.valueOf(s);
    }
    public void setLastSeen(Verdict v) { sp.edit().putString(K_LAST_SEEN, v.name()).apply(); }

    public Verdict pending() {
        String s = sp.getString(K_PENDING, null);
        return s == null ? null : Verdict.valueOf(s);
    }
    public void setPending(Verdict v) {
        if (v == null) sp.edit().remove(K_PENDING).apply();
        else sp.edit().putString(K_PENDING, v.name()).apply();
    }
}
