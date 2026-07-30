package ph.dgsd.benos.attestmon;

import android.Manifest;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Process;
import android.os.UserHandle;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/** Minimal Application: exposes a static Context + log tag the lifted parser expects. */
public class App extends Application {
    public static final String TAG = "AttestMon";
    @SuppressWarnings("StaticFieldLeak") // application context, not an Activity
    public static Context app;

    @Override
    public void onCreate() {
        super.onCreate();
        applyDefaultNotificationGrant();
        app = this;
    }

    // Default-grants POST_NOTIFICATIONS without SYSTEM_FIXED, leaving the
    // permission user-modifiable. Idempotent: prior explicit user decisions
    // and existing grants short-circuit the operation.
    //
    // getPermissionFlags(String,String,UserHandle), grantRuntimePermission(
    // String,String,UserHandle), FLAG_PERMISSION_USER_SET, and
    // FLAG_PERMISSION_USER_FIXED are @hide/@SystemApi members absent from the
    // stub android.jar used for compilation, and are therefore resolved by
    // reflection. Runtime access is permitted for the platform-signed package
    // under the signed-application hidden-API exemption.
    private void applyDefaultNotificationGrant() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return; // POST_NOTIFICATIONS is absent prior to API 33
        }
        final PackageManager pm = getPackageManager();
        final String pkg = getPackageName();
        final UserHandle user = Process.myUserHandle();
        final String perm = Manifest.permission.POST_NOTIFICATIONS;

        try {
            final int userSet = intConst(PackageManager.class, "FLAG_PERMISSION_USER_SET");
            final int userFixed = intConst(PackageManager.class, "FLAG_PERMISSION_USER_FIXED");

            final Method getFlags = PackageManager.class.getMethod(
                    "getPermissionFlags", String.class, String.class, UserHandle.class);
            final int flags = (Integer) getFlags.invoke(pm, perm, pkg, user);

            // A prior USER_SET/USER_FIXED flag indicates an explicit choice
            // and is preserved.
            if ((flags & (userSet | userFixed)) != 0) {
                return;
            }
            if (checkSelfPermission(perm) != PackageManager.PERMISSION_GRANTED) {
                final Method grant = PackageManager.class.getMethod(
                        "grantRuntimePermission", String.class, String.class, UserHandle.class);
                grant.invoke(pm, pkg, perm, user);
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            // Reflection resolution failure, SecurityException (missing
            // GRANT_RUNTIME_PERMISSIONS), IllegalArgumentException (unknown
            // permission/package), or remote failure. Non-fatal: notification
            // posting degrades to the OS-suppressed state until the user
            // grants manually.
            Log.w(TAG, "default POST_NOTIFICATIONS grant failed", e);
        }
    }

    // Resolves a static int constant by name from the given class.
    private static int intConst(Class<?> cls, String name) throws ReflectiveOperationException {
        final Field f = cls.getField(name);
        return f.getInt(null);
    }
}
