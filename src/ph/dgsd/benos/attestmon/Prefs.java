package ph.dgsd.benos.attestmon;

import android.content.Context;
import android.content.SharedPreferences;

/** Thin wrapper over SharedPreferences for the monitor's persisted state. */
public final class Prefs {
    private static final String FILE = "attestmon";
    private static final String K_FIRST_RUN    = "first_run";     // epoch ms, set once
    private static final String K_LAST_GOOD     = "last_good";     // epoch ms of last successful revocation refresh
    private static final String K_LAST_SEEN     = "last_seen";     // Verdict the user last actually saw
    private static final String K_PENDING       = "pending";       // Verdict held while locked (or null)
    private static final String K_INITIALIZED   = "initialized";   // first check recorded without notifying
    private static final String K_PHASE         = "phase";         // Phase name (poll cadence state)
    private static final String K_PHASE_DEADLINE= "phase_deadline";// epoch ms a fast phase ends (0 = none)
    private static final String K_LAST_VERDICT  = "last_verdict";  // last *computed* verdict, for transition detection

    /**
     * Epoch-ms floor below which the wall clock is treated as unset. Before a
     * network time-sync the boot clock reads the RTC default / base-ROM build
     * date, which is necessarily below any real post-flash time. teesim can't
     * fetch a keybox without network, and the clock correction lands at the same
     * moment the network comes up -- so we use this floor to keep the freshness
     * origin and the fast-phase deadlines from being poisoned by that jump.
     *
     * Set this to your BenOS build epoch. Anything at/after flash is >= this;
     * the pre-sync boot clock is below it.
     */
    public static final long CLOCK_TRUSTED_FLOOR = 1782144213000L; 

    /** True once the wall clock has advanced past the trust floor (time-synced). */
    public static boolean clockTrusted() {
        return System.currentTimeMillis() >= CLOCK_TRUSTED_FLOOR;
    }

    private final SharedPreferences sp;

    public Prefs(Context ctx) {
        sp = ctx.getApplicationContext().getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    /**
     * First-run timestamp; lazily initialised. Doubles as the freshness clock origin.
     *
     * Only latched under a trusted clock: latching a pre-sync value would anchor
     * the freshness origin years in the past and trip STALE the instant the clock
     * jumps forward. While untrusted and unset, returns a transient ~now so the
     * staleness delta stays ~0 until a real origin can be recorded.
     */
    public long firstRun() {
        long v = sp.getLong(K_FIRST_RUN, 0L);
        if (v == 0L) {
            long now = System.currentTimeMillis();
            if (!clockTrusted()) return now;      // don't persist a pre-sync value
            v = now;
            sp.edit().putLong(K_FIRST_RUN, v).apply();
        }
        return v;
    }

    /** Timestamp of the last successful live revocation-list refresh (0 if never). */
    public long lastGood() { return sp.getLong(K_LAST_GOOD, 0L); }

    /**
     * Record a successful refresh. No-op under an untrusted clock: a value latched
     * pre-sync would read as years stale the moment the clock corrects. (In
     * practice a refresh can't succeed pre-sync anyway, since there's no network;
     * this is belt-and-suspenders.)
     */
    public void setLastGoodNow() {
        if (!clockTrusted()) return;
        sp.edit().putLong(K_LAST_GOOD, System.currentTimeMillis()).apply();
    }

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

    // ---- poll-cadence phase (drives scheduling; separate from the notification path) ----

    /** Current poll cadence; NORMAL until a fast phase is entered. */
    public Phase phase() {
        String s = sp.getString(K_PHASE, null);
        return s == null ? Phase.NORMAL : Phase.valueOf(s);
    }

    /** Wall-clock epoch ms at which the current fast phase expires (0 when NORMAL). */
    public long phaseDeadline() { return sp.getLong(K_PHASE_DEADLINE, 0L); }

    /** Set phase and its window deadline atomically. */
    public void setPhase(Phase p, long deadlineEpochMs) {
        sp.edit().putString(K_PHASE, p.name())
                 .putLong(K_PHASE_DEADLINE, deadlineEpochMs)
                 .apply();
    }

    /**
     * Last verdict actually *computed* by a check (may differ from lastSeen,
     * which lags behind while the screen is locked). Used only to detect the
     * VALID -> INVALID transition that arms FAST_FLIP. Null before the first check.
     */
    public Verdict lastVerdict() {
        String s = sp.getString(K_LAST_VERDICT, null);
        return s == null ? null : Verdict.valueOf(s);
    }
    public void setLastVerdict(Verdict v) { sp.edit().putString(K_LAST_VERDICT, v.name()).apply(); }
}
