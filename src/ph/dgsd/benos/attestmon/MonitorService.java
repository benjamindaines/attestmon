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

    private static final long POLL_INTERVAL_MS = 30L * 60L * 1000L;      // 30 min
    private static final long STALE_WINDOW_MS  = 3L * 24L * 60L * 60L * 1000L; // 3 days

    private Prefs prefs;
    private AttestationChecker checker;
    private RevocationFetcher fetcher;
    private NotificationController notifier;
    private ExecutorService executor;
    private BroadcastReceiver presenceReceiver;

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = new Prefs(this);
        checker = new AttestationChecker();
        fetcher = new RevocationFetcher();
        notifier = new NotificationController(this, prefs);
        executor = Executors.newSingleThreadExecutor();
        registerPresenceReceiver();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Verdict seed = prefs.lastSeen() != null ? prefs.lastSeen() : Verdict.STALE;
        startForeground(1, notifier.buildOngoing(seed),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);

        String action = intent != null ? intent.getAction() : ACTION_START;
        if (ACTION_START.equals(action) || action == null) {
            RevocationFetcher.loadCacheIfPresent(this);
        }
        scheduleNext();
        executor.execute(this::doCheck);
        return START_STICKY;
    }

    private void doCheck() {
        try {
            fetcher.refresh(this, prefs); // updates last-good on success; no-op verdict impact on failure
            AttestationChecker.ChainResult res = checker.evaluateChain();

            boolean stale = (System.currentTimeMillis() - prefs.freshnessOrigin()) > STALE_WINDOW_MS;
            Verdict v;
            if (!res.valid)      v = Verdict.INVALID; // positively bad, regardless of freshness
            else if (stale)      v = Verdict.STALE;   // looks ok but can't confirm revocation
            else                 v = Verdict.VALID;

            Log.i(App.TAG, "check: " + v + " (" + res.detail + ", stale=" + stale + ")");
            notifier.onVerdict(v);
        } catch (Throwable t) {
            Log.e(App.TAG, "doCheck failed", t);
        }
    }

    private void scheduleNext() {
        AlarmManager am = getSystemService(AlarmManager.class);
        if (am == null) return;
        Intent i = new Intent(this, AlarmReceiver.class).setAction(ACTION_CHECK);
        PendingIntent pi = PendingIntent.getBroadcast(this, 0, i,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        long triggerAt = SystemClock.elapsedRealtime() + POLL_INTERVAL_MS;
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

    @Override
    public void onDestroy() {
        if (presenceReceiver != null) {
            try { unregisterReceiver(presenceReceiver); } catch (Throwable ignored) { }
        }
        if (executor != null) executor.shutdownNow();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
