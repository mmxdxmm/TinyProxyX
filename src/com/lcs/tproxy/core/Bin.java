package com.lcs.tproxy.core;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/** Locates and validates the native cores. APK-shipped cores live in nativeLibraryDir and are always
 *  executable; anything downloaded lands in filesDir/cores and is only exec'd if the platform allows
 *  it (root ownership on modern Android, legacy behaviour elsewhere). */
public class Bin {

    public static final String XRAY = "xray";
    public static final String TUN2SOCKS = "tun2socks";

    public static File coresDir(Context c) {
        File d = new File(c.getFilesDir(), "cores");
        if (!d.exists()) d.mkdirs();
        return d;
    }

    public static File updated(Context c, String name) {
        return new File(coresDir(c), name);
    }

    public static File shipped(Context c, String name) {
        File f = new File(c.getApplicationInfo().nativeLibraryDir, "lib" + name + ".so");
        if (f.exists()) return f;
        // some packers keep the plain name
        File g = new File(c.getApplicationInfo().nativeLibraryDir, name);
        return g.exists() ? g : null;
    }

    /** Best executable for a core: explicit override, then downloaded copy if it can really run,
     *  then the APK copy. Root mode may execute the downloaded copy from /data/local/tmp. */
    public static File resolve(Context c, String name) {
        return resolve(c, name, false);
    }

    public static File resolve(Context c, String name, boolean root) {
        String custom = com.lcs.tproxy.model.Store.I.settings.customCorePath;
        if ("xray".equals(name) && custom != null && custom.length() > 0) {
            File f = new File(custom);
            if (f.isFile()) return f;
        }
        File up = updated(c, name);
        if (up.isFile() && up.length() > 65536 && Store_preferUpdated()) {
            markExec(up);
            if (root) {
                File r = rootCopy(c, up, name);
                if (r != null) return r;
            } else if (probe(up, name)) {
                return up;
            }
        }
        return shipped(c, name);
    }

    public static File rootCopy(Context c, File up, String name) {
        try {
            File dst = new File("/data/local/tmp/tinyproxy-"
                    + android.os.Process.myUid() + "-" + name);
            String cmd = "cp " + sq(up.getAbsolutePath()) + " " + sq(dst.getAbsolutePath())
                    + " && chmod 755 " + sq(dst.getAbsolutePath());
            runAndRead(5000L, "su", "-c", cmd);
            return dst.isFile() ? dst : null;
        } catch (Throwable e) {
            return null;
        }
    }

    public static boolean hasUpdated(Context c, String name) {
        File f = updated(c, name);
        return f.isFile() && f.length() > 65536;
    }

    /** Drop the downloaded/imported copy; the APK-shipped core remains untouched. */
    public static boolean restore(Context c, String name) {
        boolean ok = true;
        File up = updated(c, name);
        if (up.exists() && !up.delete()) ok = false;
        try {
            File r = new File("/data/local/tmp/tinyproxy-"
                    + android.os.Process.myUid() + "-" + name);
            if (r.exists()) runAndRead(3000L, "su", "-c", "rm -f " + sq(r.getAbsolutePath()));
        } catch (Throwable ignored) {
        }
        return ok;
    }

    private static String sq(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    private static boolean Store_preferUpdated() {
        return com.lcs.tproxy.model.Store.I.settings.preferUpdatedCore;
    }

    public static void markExec(File f) {
        f.setReadable(true, false);
        f.setExecutable(true, false);
    }

    /** Runs the binary once to prove the kernel will actually exec it. */
    public static boolean probe(File f, String name) {
        if (f == null || !f.isFile()) return false;
        try {
            ProcessBuilder pb = new ProcessBuilder(f.getAbsolutePath(), "-version");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            drain(p.getInputStream());
            boolean done = p.waitFor(4, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) p.destroy();
            return true;
        } catch (Exception e) {
            try {
                ProcessBuilder pb = new ProcessBuilder(f.getAbsolutePath(), "version");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                drain(p.getInputStream());
                p.waitFor(4, java.util.concurrent.TimeUnit.SECONDS);
                return true;
            } catch (Exception e2) {
                return false;
            }
        }
    }

    public static String version(Context c, String name) {
        boolean root = "root".equals(com.lcs.tproxy.model.Store.I.settings.mode);
        File f = resolve(c, name, root);
        if (f == null) return "未安装";
        String arg = "version";
        String out = root
                ? runAndRead(3000L, "su", "-c", sq(f.getAbsolutePath()) + " " + arg)
                : runAndRead(f.getAbsolutePath(), arg);
        String v = firstVersionLine(out);
        if (v.length() > 0) return v;
        String state = hasUpdated(c, name)
                ? (root ? "下载版（root 运行）" : "下载版（普通模式不可执行，使用内置）")
                : marker(f);
        return state;
    }

    private static String marker(File f) {
        return f.getName() + " · " + (f.length() / 1024) + "K";
    }

    private static String firstVersionLine(String s) {
        if (s == null) return "";
        for (String line : s.split("[\\r\\n]+")) {
            line = line.trim();
            if (line.length() == 0) continue;
            if (line.toLowerCase().contains("xray")
                    || line.matches(".*\\d+\\.\\d+.*")) return line;
        }
        return "";
    }

    public static String runAndRead(String... cmd) {
        return runAndRead(2500L, cmd);
    }

    /**
     * 跑一条命令并把输出收回来。脚本里带 ROOT_APPLIED / ROOT_CLEANED / STRAYS_CLEARED
     * 这类完成标记时，见到标记立刻收工 —— iptables 有四十多条，慢机型能跑三四秒，
     * 死等 2.5 秒就把脚本半路砍了，规则只下发一半，表现是热点模式时好时坏。
     */
    public static String runAndRead(long timeoutMs, String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            InputStream in = p.getInputStream();
            StringBuilder sb = new StringBuilder();
            byte[] b = new byte[4096];
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (System.currentTimeMillis() < deadline) {
                if (in.available() > 0) {
                    int n = in.read(b);
                    if (n <= 0) break;
                    sb.append(new String(b, 0, n, "UTF-8"));
                    if (done(sb)) break;
                } else if (!p.isAlive()) break;
                else Thread.sleep(30);
            }
            p.destroy();
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean done(StringBuilder sb) {
        return sb.indexOf("ROOT_APPLIED") >= 0
                || sb.indexOf("ROOT_CLEANED") >= 0
                || sb.indexOf("STRAYS_CLEARED") >= 0;
    }

    public static void drain(final InputStream in) {
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    byte[] b = new byte[1024];
                    while (in.read(b) > 0) {
                        // discard
                    }
                } catch (Exception ignored) {
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    /** Copies a downloaded/imported core into the update slot. */
    public static boolean install(Context c, String name, InputStream in) {
        try {
            File out = updated(c, name);
            File tmp = new File(coresDir(c), name + ".tmp");
            FileOutputStream fos = new FileOutputStream(tmp);
            byte[] b = new byte[1 << 16];
            int n;
            while ((n = in.read(b)) > 0) fos.write(b, 0, n);
            fos.flush();
            fos.close();
            markExec(tmp);
            if (out.exists()) out.delete();
            if (!tmp.renameTo(out)) return false;
            markExec(out);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static List<String> readLines(File f) {
        List<String> l = new ArrayList<String>();
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(
                    new java.io.FileInputStream(f), "UTF-8"));
            String s;
            while ((s = r.readLine()) != null) l.add(s);
            r.close();
        } catch (Exception ignored) {
        }
        return l;
    }
}
