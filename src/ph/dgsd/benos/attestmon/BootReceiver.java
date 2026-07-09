package ph.dgsd.benos.attestmon;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Starts the monitor foreground service on boot. */
public final class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String a = intent.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(a)
                || Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(a)) {
            Intent svc = new Intent(context, MonitorService.class)
                    .setAction(MonitorService.ACTION_START);
            context.startForegroundService(svc);
        }
    }
}
