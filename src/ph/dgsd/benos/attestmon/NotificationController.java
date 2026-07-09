package ph.dgsd.benos.attestmon;

import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.PowerManager;

/**
 * Two channels:
 *  - STATUS (LOW, silent): the ongoing foreground-service notification.
 *  - ALERT  (HIGH, no sound, no vibration): the state-change heads-up.
 *
 * Flip alerts are only shown to a present user. If a change happens while the
 * screen is off / locked, the *latest* target state is held (older held states
 * are dropped) and posted as a heads-up the next time the device is unlocked.
 * If the net state on unlock equals what the user last saw, nothing is posted.
 */
public final class NotificationController {
    private static final String CH_STATUS = "status";
    private static final String CH_ALERT  = "alert";
    private static final int ID_ONGOING = 1;
    private static final int ID_ALERT   = 2;

    private final Context ctx;
    private final Prefs prefs;
    private final NotificationManager nm;

    public NotificationController(Context ctx, Prefs prefs) {
        this.ctx = ctx.getApplicationContext();
        this.prefs = prefs;
        this.nm = this.ctx.getSystemService(NotificationManager.class);
        ensureChannels();
    }

    private void ensureChannels() {
        NotificationChannel status = new NotificationChannel(
                CH_STATUS, "Monitor status", NotificationManager.IMPORTANCE_LOW);
        status.setShowBadge(false);
        status.setSound(null, null);

        NotificationChannel alert = new NotificationChannel(
                CH_ALERT, "Attestation change", NotificationManager.IMPORTANCE_HIGH);
        alert.setSound(null, null);          // heads-up peek, but no audio
        alert.enableVibration(false);
        alert.setVibrationPattern(null);
        alert.setShowBadge(true);

        nm.createNotificationChannel(status);
        nm.createNotificationChannel(alert);
    }

    /** Notification used for startForeground() and for ongoing status updates. */
    public Notification buildOngoing(Verdict v) {
        return new Notification.Builder(ctx, CH_STATUS)
                .setSmallIcon(iconFor(v))
                .setContentTitle(title(v))
                .setContentText(body(v))
                .setOngoing(true)
                .setShowWhen(false)
                .build();
    }

    /** Refresh the persistent status line (called every cycle). */
    public void updateOngoing(Verdict v) {
        nm.notify(ID_ONGOING, buildOngoing(v));
    }

    /** Evaluate a new verdict: update status line, and alert/hold on change. */
    public void onVerdict(Verdict current) {
        updateOngoing(current);

        if (!prefs.initialized()) {          // first ever check: record, don't alert
            prefs.setLastSeen(current);
            prefs.setInitialized();
            prefs.setPending(null);
            return;
        }
        if (current == prefs.lastSeen()) {   // no change
            prefs.setPending(null);
            return;
        }
        if (isUserPresent()) {
            postAlert(current);
            prefs.setLastSeen(current);
            prefs.setPending(null);
        } else {
            prefs.setPending(current);       // hold; single slot => keeps only the latest
        }
    }

    /** Called on unlock/screen-on: post the held alert if one is still relevant. */
    public void flushPending() {
        Verdict p = prefs.pending();
        if (p == null) return;
        if (!isUserPresent()) return;        // woke but still locked; keep holding
        if (p != prefs.lastSeen()) {
            postAlert(p);
            prefs.setLastSeen(p);
        }
        prefs.setPending(null);
    }

    private void postAlert(Verdict v) {
        Notification n = new Notification.Builder(ctx, CH_ALERT)
                .setSmallIcon(iconFor(v))
                .setContentTitle(title(v))
                .setContentText(body(v))
                .setStyle(new Notification.BigTextStyle().bigText(body(v)))
                .setCategory(Notification.CATEGORY_STATUS)
                .setAutoCancel(true)
                .build();
        nm.notify(ID_ALERT, n);              // fixed id => coalesces if user hasn't dismissed
    }

    private boolean isUserPresent() {
        PowerManager pm = ctx.getSystemService(PowerManager.class);
        KeyguardManager km = ctx.getSystemService(KeyguardManager.class);
        boolean interactive = pm != null && pm.isInteractive();
        boolean locked = km != null && km.isKeyguardLocked();
        return interactive && !locked;
    }

    private static int iconFor(Verdict v) {
        switch (v) {
            case VALID:   return android.R.drawable.presence_online;
            case STALE:   return android.R.drawable.stat_sys_warning;
            case INVALID:
            default:      return android.R.drawable.stat_notify_error;
        }
    }

    private static String title(Verdict v) {
        switch (v) {
            case VALID:   return "Attestation valid";
            case STALE:   return "Attestation unconfirmed";
            case INVALID:
            default:      return "Attestation INVALID";
        }
    }

    private static String body(Verdict v) {
        switch (v) {
            case VALID:
                return "Chain verifies to the Google root, TEE-backed, revocation list fresh.";
            case STALE:
                return "Revocation list is >3 days stale \u2014 can't confirm the keybox. "
                        + "Treat as not valid; don't rely on tap to pay.";
            case INVALID:
            default:
                return "Keybox is not currently trusted. Don't rely on tap to pay.";
        }
    }
}
