package ph.dgsd.benos.attestmon;

/**
 * Poll-cadence state. Persisted in {@link Prefs} because every poll is a fresh
 * service start (AlarmReceiver -> startForegroundService), so the phase cannot
 * live in a service field.
 *
 * NORMAL        - steady state, 30-min polls.
 * FAST_FIRSTRUN - just added ourselves to the spoof target list; poll every
 *                 5 min for 30 min to catch the first keybox pickup quickly
 *                 instead of sitting INVALID for a full 30-min cycle.
 * FAST_FLIP     - verdict just went VALID -> INVALID; poll every 15 min for
 *                 90 min to catch TEE Simulator swapping in a replacement
 *                 keybox. Its retry interval is unknown, but at 15-min polls a
 *                 90-min window catches at least one attempt whether that
 *                 interval is 5 min or an hour.
 *
 * Both fast phases exit early on the first VALID verdict, or when their window
 * elapses, dropping back to NORMAL.
 */
public enum Phase {
    NORMAL,
    FAST_FIRSTRUN,
    FAST_FLIP
}
