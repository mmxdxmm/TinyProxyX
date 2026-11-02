package com.lcs.tproxy.core;

import android.content.Context;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Downloads cores and geo data. Three sources: bundled default url, custom url, local file. */
public class Updater {

    public static final String XRAY_URL =
            "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-android-arm64-v8a.zip";
    /* 规则库跟核心同一家：跑的是 xray，就用 xray 自己的 geoip/geosite。
     * v2fly 那份是给 v2ray 的，两边的 geosite 标签集合与 geoip 切分都不一样，
     * 拿 v2fly 的数据喂 xray，规则里写的标签可能根本不存在。
     * XTLS 的 release 没挂资源时再退回 v2fly，至少别让人卡在「更新失败」。 */
    public static final String GEOIP_URL =
            "https://github.com/XTLS/Xray-core/releases/latest/download/geoip.dat";
    public static final String GEOSITE_URL =
            "https://github.com/XTLS/Xray-core/releases/latest/download/geosite.dat";
    public static final String GEOIP_FALLBACK =
            "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat";
    public static final String GEOSITE_FALLBACK =
            "https://github.com/v2fly/domain-list-community/releases/latest/download/geosite.dat";

    public interface Cb {
        void onLog(String line);

        void onDone(boolean ok, String message);
    }

    /** result of a version probe: null version means "no upstream feed for this core" */
    public static class Check {
        public String version = "";
        public String url = "";
        public String note = "";
    }

    /** Ask the upstream what the newest xray is. Never downloads. */
    public static void checkXray(final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    HttpURLConnection c = open("https://api.github.com/repos/XTLS/Xray-core/releases/latest");
                    java.io.InputStream in = c.getInputStream();
                    java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
                    in.close();
                    org.json.JSONObject o = new org.json.JSONObject(new String(b.toByteArray(), "UTF-8"));
                    String tag = o.optString("tag_name", "");
                    org.json.JSONArray assets = o.optJSONArray("assets");
                    String url = "";
                    for (int i = 0; assets != null && i < assets.length(); i++) {
                        org.json.JSONObject a = assets.optJSONObject(i);
                        String nm = a.optString("name", "");
                        if (nm.contains("android-arm64")) {
                            url = a.optString("browser_download_url", "");
                            break;
                        }
                    }
                    done(cb, true, "最新版本 " + tag + (url.length() > 0 ? "" : "（未找到 arm64 包）") + "\\n" + url);
                } catch (Exception e) {
                    done(cb, false, "查询失败: " + e.getClass().getSimpleName());
                }
            }
        }).start();
    }

    public static void run(final Cb cb, final String startMsg) {
        if (cb != null) cb.onLog(startMsg);
    }

    /** Downloads and installs the xray core. Runs on a worker thread. */
    public static void updateXray(final Context c, final String url, final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    log(cb, "下载 " + url);
                    HttpURLConnection conn = open(url);
                    InputStream in = new BufferedInputStream(conn.getInputStream(), 1 << 16);
                    int code = conn.getResponseCode();
                    if (code >= 400) {
                        done(cb, false, "HTTP " + code);
                        return;
                    }
                    byte[] head = new byte[4];
                    InputStream data = peek(in, head);
                    boolean zip = head[0] == 'P' && head[1] == 'K';
                    boolean ok;
                    if (zip) {
                        File tmp = new File(Bin.coresDir(c), "xray.bin");
                        if (!unzipFirst(data, "xray", tmp)) {
                            done(cb, false, "压缩包里没有 xray");
                            return;
                        }
                        InputStream fi = new java.io.FileInputStream(tmp);
                        ok = Bin.install(c, Bin.XRAY, fi);
                        fi.close();
                        tmp.delete();
                    } else {
                        ok = Bin.install(c, Bin.XRAY, data);
                    }
                    if (!ok) {
                        done(cb, false, "写入失败");
                        return;
                    }
                    File got = Bin.updated(c, Bin.XRAY);
                    boolean rootMode = "root".equals(com.lcs.tproxy.model.Store.I.settings.mode);
                    boolean exec = (rootMode && Bin.rootCopy(c, got, Bin.XRAY) != null)
                            || Bin.probe(got, Bin.XRAY);
                    done(cb, true, exec
                            ? "已更新：" + Bin.version(c, Bin.XRAY)
                            : "已下载 " + (got.length() >> 20) + "MB；普通模式不能从应用目录执行，"
                            + "切到 ROOT 模式会自动复制到 /data/local/tmp 运行。");
                } catch (Exception e) {
                    done(cb, false, e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        }).start();
    }

    private static final Object GEO_LOCK = new Object();

    public static void updateGeo(final Context c, final Cb cb) {
        updateGeoBoth(c, cb);
    }

    /** Replace both databases together from the same Xray release zip. No v2fly mixing. */
    public static void updateGeoBoth(final Context c, final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                synchronized (GEO_LOCK) {
                    File zip = new File(Engine.I.assetDir(c), "xray-geo.zip");
                    try {
                        log(cb, "下载 Xray 发布包，提取 geoip.dat + geosite.dat");
                        if (!fetchTo(new URL(XRAY_URL), zip)) {
                            done(cb, false, "Xray 发布包下载失败；未改动现有规则库");
                            return;
                        }
                        File dir = Engine.I.assetDir(c);
                        File a = new File(dir, "geoip.dat.new");
                        File b = new File(dir, "geosite.dat.new");
                        if (!extract(zip, "geoip.dat", a) || !extract(zip, "geosite.dat", b)) {
                            a.delete();
                            b.delete();
                            zip.delete();
                            done(cb, false, "发布包里没有完整的 geoip/geosite；未改动现有规则库");
                            return;
                        }
                        if (!validGeo(a) || !validGeo(b)) {
                            a.delete();
                            b.delete();
                            zip.delete();
                            done(cb, false, "规则库不是有效的 geo 数据（或误存成 zip）；未改动现有文件");
                            return;
                        }
                        if (!replace(a, new File(dir, "geoip.dat"))
                                || !replace(b, new File(dir, "geosite.dat"))) {
                            done(cb, false, "写入规则库失败");
                            return;
                        }
                        zip.delete();
                        copyToRootAsset(c, "geoip.dat");
                        copyToRootAsset(c, "geosite.dat");
                        done(cb, true, "geoip.dat / geosite.dat 已同源更新");
                    } catch (Exception e) {
                        zip.delete();
                        done(cb, false, e.toString());
                    }
                }
            }
        }).start();
    }

    private static boolean extract(File zip, String name, File out) {
        try {
            java.io.FileInputStream in = new java.io.FileInputStream(zip);
            boolean ok = unzipFirst(in, name, out);
            in.close();
            return ok;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean replace(File src, File dst) {
        if (dst.exists()) dst.delete();
        return src.renameTo(dst);
    }

    /** Reject a zip/html/truncated payload masquerading as geoip/geosite. */
    private static boolean validGeo(File f) {
        if (f == null || f.length() < (1 << 20)) return false;
        try {
            java.io.FileInputStream in = new java.io.FileInputStream(f);
            int a = in.read();
            int b = in.read();
            in.close();
            return !(a == 'P' && b == 'K');
        } catch (Exception e) {
            return false;
        }
    }

    /** Update one database from the Xray release zip only; never mix in v2fly data. */
    public static void updateGeoOne(final Context c, final String name, final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                synchronized (GEO_LOCK) {
                    try {
                        File out = new File(Engine.I.assetDir(c), name);
                        log(cb, "从 Xray 发布包提取 " + name);
                        if (!fetchGeoFromXray(cb, out, name)) {
                            done(cb, false, name + " 更新失败；未改动现有规则库");
                            return;
                        }
                        copyToRootAsset(c, name);
                        done(cb, true, name + " 已更新");
                    } catch (Exception e) {
                        done(cb, false, e.toString());
                    }
                }
            }
        }).start();
    }

    /** Import one database from a local file. */
    public static void importGeo(final Context c, final String name, final InputStream in, final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    File out = new File(Engine.I.assetDir(c), name);
                    File tmp = new File(out.getParentFile(), name + ".tmp");
                    OutputStream fos = new FileOutputStream(tmp);
                    byte[] b = new byte[1 << 16];
                    int n;
                    while ((n = in.read(b)) > 0) fos.write(b, 0, n);
                    fos.flush();
                    fos.close();
                    in.close();
                    if (!validGeo(tmp)) {
                        tmp.delete();
                        done(cb, false, "文件不是有效的 " + name + "（或误存成 zip）");
                        return;
                    }
                    if (out.exists()) out.delete();
                    if (!tmp.renameTo(out)) {
                        done(cb, false, "写入失败");
                        return;
                    }
                    copyToRootAsset(c, name);
                    done(cb, true, name + " 已导入");
                } catch (Exception e) {
                    done(cb, false, e.toString());
                }
            }
        }).start();
    }

    /** Restore the APK-shipped copy of one database. */
    public static void restoreGeo(final Context c, final String name, final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    File out = new File(Engine.I.assetDir(c), name);
                    InputStream in = c.getAssets().open(name);
                    File tmp = new File(out.getParentFile(), name + ".tmp");
                    OutputStream fos = new FileOutputStream(tmp);
                    byte[] b = new byte[1 << 16];
                    int n;
                    while ((n = in.read(b)) > 0) fos.write(b, 0, n);
                    fos.flush();
                    fos.close();
                    in.close();
                    if (out.exists()) out.delete();
                    if (!tmp.renameTo(out)) {
                        done(cb, false, "还原失败");
                        return;
                    }
                    copyToRootAsset(c, name);
                    done(cb, true, name + " 已还原内置版本");
                } catch (Exception e) {
                    done(cb, false, e.toString());
                }
            }
        }).start();
    }

    private static boolean fetchGeoFromXray(Cb cb, File out, String name) {
        File zip = new File(out.getParentFile(), "xray-geo-" + name + ".tmp");
        try {
            if (!fetchTo(new URL(XRAY_URL), zip)) return false;
            File one = new File(out.getParentFile(), name + ".xray");
            java.io.FileInputStream in = new java.io.FileInputStream(zip);
            boolean ok = unzipFirst(in, name, one);
            in.close();
            zip.delete();
            if (!ok || !validGeo(one)) {
                one.delete();
                return false;
            }
            if (out.exists()) out.delete();
            boolean moved = one.renameTo(out);
            if (!moved) one.delete();
            return moved;
        } catch (Exception e) {
            zip.delete();
            return false;
        }
    }

    /** 依次试 urls，第一个成功的算数。前面的源挂了（release 没挂资源 / 被墙）就换下一个，
     *  别让规则库卡在单一来源上。 */
    private static boolean fetchAny(Cb cb, File out, String name, String... urls) {
        for (int i = 0; i < urls.length; i++) {
            try {
                if (fetchTo(new URL(urls[i]), out)) {
                    if (i > 0) log(cb, name + " 已回退到备份源");
                    return true;
                }
            } catch (Exception e) {
                log(cb, name + " 源失败：" + e.getClass().getSimpleName());
            }
        }
        return false;
    }

    public static void importLocal(final Context c, final InputStream in, final String name, final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    byte[] head = new byte[4];
                    InputStream data = peek(in, head);
                    boolean ok;
                    if (head[0] == 'P' && head[1] == 'K') {
                        File tmp = new File(Bin.coresDir(c), "import.bin");
                        if (!unzipFirst(data, name, tmp)) {
                            done(cb, false, "压缩包里没有 " + name);
                            return;
                        }
                        java.io.FileInputStream fi = new java.io.FileInputStream(tmp);
                        ok = Bin.install(c, name, fi);
                        fi.close();
                        tmp.delete();
                    } else {
                        ok = Bin.install(c, name, data);
                    }
                    if (!ok) {
                        done(cb, false, "导入失败");
                        return;
                    }
                    boolean exec = Bin.probe(Bin.updated(c, name), name);
                    done(cb, true, exec ? "导入成功：" + Bin.version(c, name)
                            : "已导入，但系统禁止直接执行；ROOT 模式可用。");
                } catch (Exception e) {
                    done(cb, false, e.toString());
                }
            }
        }).start();
    }

    /** Plain text fetch, used by subscription updates. */
    public static String fetchText(String url) {
        try {
            HttpURLConnection c = open(url);
            if (c.getResponseCode() >= 400) return "";
            java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
            InputStream in = c.getInputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
            in.close();
            return new String(b.toByteArray(), "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }

    /* ------------------------------------------------------------------ utils */

    private static HttpURLConnection open(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(20000);
        conn.setReadTimeout(60000);
        conn.setRequestProperty("User-Agent", "TinyProxyX/1.0");
        conn.connect();
        return conn;
    }

    private static boolean fetchTo(URL url, File out) {
        try {
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setInstanceFollowRedirects(true);
            conn.setConnectTimeout(20000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("User-Agent", "TinyProxyX/1.0");
            if (conn.getResponseCode() >= 400) return false;
            InputStream in = conn.getInputStream();
            File tmp = new File(out.getParentFile(), out.getName() + ".tmp");
            OutputStream fos = new FileOutputStream(tmp);
            byte[] b = new byte[1 << 16];
            int n;
            while ((n = in.read(b)) > 0) fos.write(b, 0, n);
            fos.flush();
            fos.close();
            in.close();
            if (tmp.length() < 1024) return false;
            if (out.exists()) out.delete();
            return tmp.renameTo(out);
        } catch (Exception e) {
            return false;
        }
    }

    private static void copyToRootAsset(Context c, String name) {
        try {
            File src = new File(Engine.I.assetDir(c), name);
            File dst = new File(c.getFilesDir(), name);
            java.io.FileInputStream in = new java.io.FileInputStream(src);
            OutputStream out = new FileOutputStream(dst);
            byte[] b = new byte[1 << 16];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
            out.close();
            in.close();
        } catch (Exception ignored) {
        }
    }

    private static InputStream peek(InputStream in, byte[] head) throws Exception {
        int got = 0;
        while (got < head.length) {
            int n = in.read(head, got, head.length - got);
            if (n <= 0) break;
            got += n;
        }
        return new java.io.SequenceInputStream(
                new java.io.ByteArrayInputStream(head, 0, got), in);
    }

    private static boolean unzipFirst(InputStream zip, String entryName, File out) {
        try {
            ZipInputStream z = new ZipInputStream(new BufferedInputStream(zip));
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                String n = e.getName();
                if (n.endsWith("/")) continue;
                String base = n.contains("/") ? n.substring(n.lastIndexOf('/') + 1) : n;
                if (!base.equals(entryName) && !base.equals(entryName + ".exe")
                        && !base.equals("lib" + entryName + ".so")) continue;
                OutputStream fos = new FileOutputStream(out);
                byte[] b = new byte[1 << 16];
                int k;
                while ((k = z.read(b)) > 0) fos.write(b, 0, k);
                fos.flush();
                fos.close();
                return out.length() > 4096;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private static void log(Cb cb, String s) {
        if (cb != null) cb.onLog(s);
    }

    private static void done(Cb cb, boolean ok, String s) {
        if (cb != null) cb.onDone(ok, s);
    }
}

