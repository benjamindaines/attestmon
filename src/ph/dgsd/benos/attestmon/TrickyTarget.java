package ph.dgsd.benos.attestmon;

import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/**
 * Self-registers this package in TrickyStore / TEE-Simulator's target list so
 * the keybox spoof applies to attestmon's own probe key. As a system app we are
 * not auto-added; without this the monitor polls while it is not a spoof target
 * and reports INVALID indefinitely.
 *
 * Append-in-place, never rewrite: TrickyStore watches the file inode with a
 * FileObserver and live-reloads on CLOSE_WRITE, so a plain append triggers an
 * immediate reload with no reboot. An atomic temp+rename would move the watch
 * off the live inode. The try-with-resources close() below is what emits
 * CLOSE_WRITE.
 *
 * Idempotent: a whole-line match means we are already listed and we do nothing,
 * so the file does not grow by a line every boot.
 */
public final class TrickyTarget {
    // TrickyStore's target file (singular "target.txt"). TEE Simulator forks
    // read the same path. If your build differs, change this one line.
    //
    // target.txt gets clobbered in -307, need to move to auto_added.txt
    static final String TARGET_PATH = "/data/adb/tricky_store/.automation/auto_added.txt";

    private TrickyTarget() {}

    /**
     * Ensure {@code pkg} is present in the target file.
     *
     * @return true only if we just added it (it was absent and the append
     *         succeeded); false if it was already listed, the module dir is
     *         missing, or the write failed.
     */
    public static boolean ensureListed(String pkg) {
        File f = new File(TARGET_PATH);
        try {
            if (f.exists()) {
                List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
                for (String line : lines) {
                    if (line.trim().equals(pkg)) {
                        return false; // already listed
                    }
                }
            } else {
                File parent = f.getParentFile();
                if (parent == null || !parent.isDirectory()) {
                    // Module dir absent -> TrickyStore/TEE-Sim not installed.
                    // Don't fabricate config for an absent module.
                    Log.w(App.TAG, "tricky: target dir missing, not registering (" + TARGET_PATH + ")");
                    return false;
                }
                // Dir exists but file doesn't: creating it fresh means its
                // SELinux label comes from the parent's type_transition. If
                // TrickyStore can't read it afterward, verify the new file is
                // labelled adb_data_file like the rest of the dir.
            }
            // Append -> close() fires CLOSE_WRITE -> FileObserver reload.
            try (FileWriter w = new FileWriter(f, /* append */ true)) {
                w.write(pkg + "\n");
            }
            Log.i(App.TAG, "tricky: added " + pkg + " to target list");
            return true;
        } catch (Throwable t) {
            // Most likely an SELinux denial. Confirm the attestmon domain has
            // search on the tricky_store dir and read/write/append/getattr on
            // the file's type; a denial here fails silently and the append
            // vanishes. Check: dmesg | grep attestmon.
            Log.w(App.TAG, "tricky: register failed (" + t.getClass().getSimpleName() + ")", t);
            return false;
        }
    }
}
