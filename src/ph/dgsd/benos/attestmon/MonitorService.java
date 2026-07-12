package ph.dgsd.benos.attestmon;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ServiceInfo;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Log;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MonitorService extends Service {
    static final String ACTION_START = "ph.dgsd.benos.attestmon.START";
    static final String ACTION_CHECK = "ph.dgsd.benos.attestmon.CHECK";

    // Poll intervals per phase.
    private static final long POLL_NORMAL_MS   = 30L * 60L * 1000L;   // 30 min
    private static final long POLL_FIRSTRUN_MS =  5L * 60L * 1000L;   //  5 min
    private static final long POLL_FLIP_MS     = 15L * 60L * 1000L;   // 15 min
    private static final long POLL_UNTRUSTED_MS = 5L * 60L * 1000L;   // retry cadence while clock < trust floor

    // Fast-phase window durations.
    private static final long WINDOW_FIRSTRUN_MS = 30L * 60L * 1000L; // 30 min
    private static final long WINDOW_FLIP_MS     = 90L * 60L * 1000L; // 90 min

    private static final long STALE_WINDOW_MS  = 3L * 24L * 60L * 60L * 1000L; // 3 days

    private Prefs prefs;
    private AttestationChecker checker;
    private RevocationFetcher fetcher;
    private NotificationController notifier;
    private ExecutorService executor;
    private BroadcastReceiver presenceReceiver;
    private BroadcastReceiver clockReceiver;

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = new Prefs(this);
        checker = new AttestationChecker();
        fetcher = new RevocationFetcher();
        notifier = new NotificationController(this, prefs);
        executor = Executors.newSingleThreadExecutor();
        registerPresenceReceiver();
        registerClockReceiver();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Verdict seed = prefs.lastSeen() != null ? prefs.lastSeen() : Verdict.STALE;
        startForeground(1, notifier.buildOngoing(seed),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);

        String action = intent != null ? intent.getAction() : ACTION_START;
        boolean isStart = ACTION_START.equals(action) || action == null;
        if (isStart) {
            RevocationFetcher.loadCacheIfPresent(this);
        }

        // Safety-net alarm at the currently persisted phase interval, in case the
        // process is killed before doCheck runs. doCheck reschedules the same
        // PendingIntent (FLAG_UPDATE_CURRENT) once the post-check phase is known,
        // so at most one alarm ever exists.
        scheduleNext(prefs.phase());

        executor.execute(() -> doCheck(isStart));
        return START_STICKY;
    }

    private void doCheck(boolean isStart) {
        // Don't run the check until the wall clock is past the trust floor.
        // Pre-sync the clock reads the base-ROM build date and there's no network
        // yet, so teesim can't have a keybox and any verdict now is meaningless --
        // worse, it would latch a bogus freshness origin / phase state. Defer and
        // retry soon; registerClockReceiver() also kicks a check the instant time
        // syncs, so in practice the first real check lands right at correction.
        if (!Prefs.clockTrusted()) {
            Log.i(App.TAG, "clock below trust floor; deferring check until time sync");
            scheduleIn(POLL_UNTRUSTED_MS);
            return;
        }
        try {
            // Keep ourselves on the spoof target list *before* generating the
            // probe key, so the spoof applies to it. A newly-added event (at any
            // time) means the keybox pickup is imminent -> first-run fast phase.
            boolean newlyAdded = TrickyTarget.ensureListed(getPackageName());

            fetcher.refresh(this, prefs); // updates last-good on success; no verdict impact on failure
            AttestationChecker.ChainResult res = checker.evaluateChain();

            boolean stale = (System.currentTimeMillis() - prefs.freshnessOrigin()) > STALE_WINDOW_MS;
            Verdict v;
            if (!res.valid)      v = Verdict.INVALID; // positively bad, regardless of freshness
            else if (stale)      v = Verdict.STALE;   // looks ok but can't confirm revocation
            else                 v = Verdict.VALID;

            Log.i(App.TAG, "check: " + v + " (" + res.detail + ", stale=" + stale + ")");

            applyPhase(isStart, newlyAdded, v);
            notifier.onVerdict(v);
        } catch (Throwable t) {
            Log.e(App.TAG, "doCheck failed", t);
        } finally {
            // Reschedule at the (possibly updated) phase interval. In finally so a
            // failed check never orphans the monitor.
            scheduleNext(prefs.phase());
        }
    }

    /**
     * Resolve the poll cadence for the next cycle and persist the computed verdict.
     *
     * Transition rules (evaluated in order):
     *   - newly added to the target list  -> FAST_FIRSTRUN (5 min polls, 30-min window)
     *   - fresh start, already listed      -> NORMAL, unless a fast phase is still
     *                                         live, which is preserved across reboot
     *   - verdict VALID -> INVALID         -> FAST_FLIP (15 min polls, 90-min window)
     *   - any fast phase, verdict VALID     -> NORMAL (early exit)
     *   - any fast phase, window elapsed    -> NORMAL
     *
     * Clock-jump handling: deadlines are wall-clock epoch ms so a fast phase can
     * survive a reboot. But the pre-time-sync boot clock is wrong, so a deadline
     * anchored before sync becomes meaningless the instant the clock corrects
     * (which is also when the network -- and thus teesim's keybox -- comes up).
     * Two guards keep that jump from silently demoting us to 30-min polls:
     *   1. A deadline anchored under an untrusted clock (deadline < trust floor)
     *      is re-anchored to a fresh full window from the now-trusted clock.
     *   2. Time-based expiry only applies once the clock is trusted, so the
     *      pre-sync window never expires the fast phase.
     *
     * lastVerdict is tracked here independently of the notifier's lastSeen so the
     * flip is detected from the *actual* verdict even when alerts are held (locked).
     */
    private void applyPhase(boolean isStart, boolean newlyAdded, Verdict v) {
        long now = System.currentTimeMillis();
        boolean trusted = Prefs.clockTrusted();
        Phase phase = prefs.phase();
        long deadline = prefs.phaseDeadline();
        Verdict prev = prefs.lastVerdict();

        // (1) Re-anchor a deadline that was set under the pre-sync clock. A good
        // deadline is always >= the trust floor (now >= floor + window); a poisoned
        // one is below it. Give a fresh full window from the corrected clock.
        if (phase != Phase.NORMAL && trusted && deadline != 0L
                && deadline < Prefs.CLOCK_TRUSTED_FLOOR) {
            deadline = now + windowFor(phase);
        }

        // Under an untrusted clock, never treat the phase as expired.
        boolean liveFastPhase = phase != Phase.NORMAL && (!trusted || now < deadline);
        if (newlyAdded) {
            phase = Phase.FAST_FIRSTRUN;
            deadline = now + WINDOW_FIRSTRUN_MS;
        } else if (isStart && !liveFastPhase) {
            // Fresh boot resets to NORMAL, but a still-live fast phase is kept
            // (with its original deadline) across the reboot, so a flip recovery
            // or warmup keeps fast-polling instead of dropping to 30 min.
            phase = Phase.NORMAL;
            deadline = 0L;
        }

        // A genuine drop outranks first-run warmup: prefer the longer flip window.
        if (prev == Verdict.VALID && v == Verdict.INVALID) {
            phase = Phase.FAST_FLIP;
            deadline = now + WINDOW_FLIP_MS;
        }

        // (2) Early exit / expiry. VALID always exits a fast phase; time-based
        // expiry only once the clock is trusted.
        if (phase != Phase.NORMAL && (v == Verdict.VALID || (trusted && now >= deadline))) {
            phase = Phase.NORMAL;
            deadline = 0L;
        }

        prefs.setPhase(phase, deadline);
        prefs.setLastVerdict(v);
    }

    private long windowFor(Phase p) {
        switch (p) {
            case FAST_FIRSTRUN: return WINDOW_FIRSTRUN_MS;
            case FAST_FLIP:     return WINDOW_FLIP_MS;
            case NORMAL:
            default:            return 0L;
        }
    }

    private long intervalFor(Phase p) {
        switch (p) {
            case FAST_FIRSTRUN: return POLL_FIRSTRUN_MS;
            case FAST_FLIP:     return POLL_FLIP_MS;
            case NORMAL:
            default:            return POLL_NORMAL_MS;
        }
    }

    private void scheduleNext(Phase phase) {
        scheduleIn(intervalFor(phase));
    }

    private void scheduleIn(long intervalMs) {
        AlarmManager am = getSystemService(AlarmManager.class);
        if (am == null) return;
        Intent i = new Intent(this, AlarmReceiver.class).setAction(ACTION_CHECK);
        PendingIntent pi = PendingIntent.getBroadcast(this, 0, i,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        long triggerAt = SystemClock.elapsedRealtime() + intervalMs;
        try {
            if (am.canScheduleExactAlarms()) {
                am.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi);
            } else {
                am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi);
            }
        } catch (SecurityException e) {
            am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi);
        }
    }

    private void registerPresenceReceiver() {
        presenceReceiver = new BroadcastReceiver() {
            @Override public void onReceive(Context c, Intent i) {
                notifier.flushPending(); // onReceive is on the main thread; posting is light
            }
        };
        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_USER_PRESENT);
        filter.addAction(Intent.ACTION_SCREEN_ON);
        registerReceiver(presenceReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
    }

    /**
     * The pre-network boot clock is wrong; NITZ/NTP corrects it right when the
     * network (and thus teesim's keybox) comes up. If we're mid fast-phase, that
     * phase's deadline was anchored to the bad clock -- so on the correction, kick
     * an immediate check. applyPhase re-anchors the deadline and we surface the
     * fresh verdict now instead of waiting up to a full poll interval. Ignored in
     * NORMAL so ordinary time adjustments don't trigger check storms -- except
     * when we've never completed a check (initialized() is false), which means
     * the first run was deferred by the trust-floor gate in doCheck; then the
     * correcting jump is exactly our cue to run it, so we kick even in NORMAL.
     */
    private void registerClockReceiver() {
        clockReceiver = new BroadcastReceiver() {
            @Override public void onReceive(Context c, Intent i) {
                boolean deferredFirstRun = !prefs.initialized();
                if (Prefs.clockTrusted()
                        && (prefs.phase() != Phase.NORMAL || deferredFirstRun)) {
                    Intent svc = new Intent(c, MonitorService.class).setAction(ACTION_CHECK);
                    c.startForegroundService(svc);
                }
            }
        };
        registerReceiver(clockReceiver, new IntentFilter(Intent.ACTION_TIME_CHANGED),
                Context.RECEIVER_NOT_EXPORTED);
    }

    @Override
    public void onDestroy() {
        if (presenceReceiver != null) {
            try { unregisterReceiver(presenceReceiver); } catch (Throwable ignored) { }
        }
        if (clockReceiver != null) {
            try { unregisterReceiver(clockReceiver); } catch (Throwable ignored) { }
        }
        if (executor != null) executor.shutdownNow();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
