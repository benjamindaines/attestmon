package ph.dgsd.benos.attestmon;

import android.os.FileObserver;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.RandomAccessFile;
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
    static final String CONFIG_DIR = "/data/adb/tricky_store";
    static final String TARGET_PATH = CONFIG_DIR + "/target.txt";

    // Held to prevent the observer being garbage-collected; FileObserver stops
    // delivering events once collected.
    private static FileObserver selfHealObserver;

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
                    if (stripSuffix(line.trim()).equals(pkg)) {
                        return false;
                    }
                }
            } else {
                File parent = f.getParentFile();
                if (parent == null || !parent.isDirectory()) {
                    Log.w(App.TAG, "tricky: config dir missing, not registering (" + CONFIG_DIR + ")");
                    return false;
                }
                // Dir exists but file doesn't: creating it fresh means its
                // SELinux label comes from the parent's type_transition. If
                // TrickyStore can't read it afterward, verify the new file is
                // labelled adb_data_file like the rest of the dir.
            }
            appendLine(f, pkg);
            Log.i(App.TAG, "tricky: added " + pkg + " to target.txt");
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

    /**
     * Install a watcher that re-adds pkg whenever target.txt changes and the
     * package is no longer present. Idempotent: repeated calls replace the
     * prior observer.
     */
    public static synchronized void startSelfHeal(final String pkg) {
        if (!new File(CONFIG_DIR).isDirectory()) {
            Log.w(App.TAG, "tricky: config dir missing, self-heal not started");
            return;
        }
        if (selfHealObserver != null) {
            selfHealObserver.stopWatching();
            selfHealObserver = null;
        }
        final int mask = FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO | FileObserver.MODIFY;
        selfHealObserver = new FileObserver(TARGET_PATH, mask) {
            @Override public void onEvent(int event, String path) {
                try {
                    if (ensureListed(pkg)) {
                        Log.i(App.TAG, "tricky: re-added " + pkg + " after target.txt change");
                    }
                } catch (Throwable t) {
                    Log.w(App.TAG, "tricky: self-heal re-add failed", t);
                }
            }
        };
        selfHealObserver.startWatching();
        Log.i(App.TAG, "tricky: self-heal observer watching " + TARGET_PATH);
    }

    private static String stripSuffix(String line) {
        if (line.endsWith("!") || line.endsWith("?")) {
            return line.substring(0, line.length() - 1).trim();
        }
        return line;
    }

    private static void appendLine(File f, String pkg) throws Exception {
        // A regenerating writer may leave target.txt without a trailing
        // newline; a bare append would then join this package to the last
        // line. Prepend a newline only in that case.
        boolean needsLeadingNewline = false;
        if (f.exists() && f.length() > 0) {
            byte[] tail = new byte[1];
            try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
                raf.seek(f.length() - 1);
                raf.readFully(tail);
            }
            needsLeadingNewline = tail[0] != (byte) '\n';
        }
        try (FileWriter w = new FileWriter(f, /* append */ true)) {
            if (needsLeadingNewline) w.write("\n");
            w.write(pkg + "\n");
        }
    }
}
