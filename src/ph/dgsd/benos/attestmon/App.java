package ph.dgsd.benos.attestmon;

import android.app.Application;
import android.content.Context;

/** Minimal Application: exposes a static Context + log tag the lifted parser expects. */
public class App extends Application {
    public static final String TAG = "AttestMon";
    @SuppressWarnings("StaticFieldLeak") // application context, not an Activity
    public static Context app;

    @Override
    public void onCreate() {
        super.onCreate();
        app = this;
    }
}
