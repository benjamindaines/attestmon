package ph.dgsd.benos.attestmon;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Wakes the service each poll interval to run a check and reschedule. */
public final class AlarmReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Intent svc = new Intent(context, MonitorService.class)
                .setAction(MonitorService.ACTION_CHECK);
        context.startForegroundService(svc);
    }
}
