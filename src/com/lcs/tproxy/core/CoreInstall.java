package com.lcs.tproxy.core;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Per-core install / update. Only xray is left: the gost engine was removed in 1.8.2. */
public class CoreInstall {

    public static final String[] NAMES = {Bin.XRAY};
    public static final String[] LABELS = {"Xray 核心"};
    public static final String[] DEFAULT_URL = {
            "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-android-arm64-v8a.zip"};

    public interface Cb {
        void onDone(boolean ok, String message);
    }

    public static String label(String core) {
        int i = 0;
        String out = core;
        while (i < NAMES.length) {
            out = NAMES[i].equals(core) ? LABELS[i] : out;
            i++;
        }
        return out;
    }

    private static HttpURLConnection open(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setInstanceFollowRedirects(true);
        c.setConnectTimeout(20000);
        c.setReadTimeout(60000);
        c.setRequestProperty("User-Agent", "TinyProxyX/1.0");
        return c;
    }

    public static String customUrl(String core) {
        String u = com.lcs.tproxy.model.Store.I.settings.coreUrls.get(core);
        if (u != null && u.length() > 0) return u;
        int i = 0;
        String out = "";
        while (i < NAMES.length) {
            out = NAMES[i].equals(core) ? DEFAULT_URL[i] : out;
            i++;
        }
        return out;
    }

    public static void setCustomUrl(String core, String url) {
        com.lcs.tproxy.model.Store.I.settings.coreUrls.put(core, url == null ? "" : url.trim());
        com.lcs.tproxy.model.Store.I.save();
    }

    /** Latest upstream tag for xray; "" when the core has no feed. */
    public static String[] checkUpstream(String core) {
        if (!Bin.XRAY.equals(core)) return new String[]{"", ""};
        try {
            HttpURLConnection c = open("https://api.github.com/repos/XTLS/Xray-core/releases/latest");
            if (c.getResponseCode() >= 400) return new String[]{"", ""};
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            InputStream in = c.getInputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
            in.close();
            JSONObject o = new JSONObject(new String(b.toByteArray(), "UTF-8"));
            String tag = o.optString("tag_name", "");
            String url = "";
            JSONArray assets = o.optJSONArray("assets");
            for (int i = 0; assets != null && i < assets.length(); i++) {
                JSONObject a = assets.optJSONObject(i);
                if (a.optString("name", "").contains("android-arm64")) {
                    url = a.optString("browser_download_url", "");
                    break;
                }
            }
            return new String[]{tag, url};
        } catch (Exception e) {
            return new String[]{"", ""};
        }
    }

    public static void download(final Context c, final String core, final String url, final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    HttpURLConnection conn = open(url);
                    if (conn.getResponseCode() >= 400) {
                        report(cb, false, "HTTP " + conn.getResponseCode());
                        return;
                    }
                    ByteArrayOutputStream mem = new ByteArrayOutputStream();
                    InputStream in = new BufferedInputStream(conn.getInputStream(), 1 << 16);
                    byte[] buf = new byte[1 << 16];
                    int n;
                    while ((n = in.read(buf)) > 0) mem.write(buf, 0, n);
                    in.close();
                    installBytes(c, core, mem.toByteArray(), cb);
                } catch (Exception e) {
                    report(cb, false, e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        }).start();
    }

    public static void importFile(final Context c, final String core, final InputStream in, final Cb cb) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    ByteArrayOutputStream mem = new ByteArrayOutputStream();
                    byte[] buf = new byte[1 << 16];
                    int n;
                    while ((n = in.read(buf)) > 0) mem.write(buf, 0, n);
                    installBytes(c, core, mem.toByteArray(), cb);
                } catch (Exception e) {
                    report(cb, false, e.toString());
                }
            }
        }).start();
    }

    private static void installBytes(Context c, String core, byte[] data, Cb cb) {
        boolean zip = data.length > 2 && data[0] == 'P' && data[1] == 'K';
        byte[] payload = data;
        if (zip) {
            payload = entry(data, core);
            if (payload == null) {
                report(cb, false, "压缩包里没有 " + core);
                return;
            }
        }
        File dir = Bin.coresDir(c);
        File tmp = new File(dir, core + ".tmp");
        try {
            OutputStream out = new FileOutputStream(tmp);
            out.write(payload);
            out.flush();
            out.close();
            Bin.markExec(tmp);
            File dst = Bin.updated(c, core);
            boolean moved = tmp.renameTo(dst);
            if (!moved) {
                dst.delete();
                moved = tmp.renameTo(dst);
            }
            if (!moved) {
                report(cb, false, "写入失败");
                return;
            }
            Bin.markExec(dst);
            boolean rootMode = "root".equals(com.lcs.tproxy.model.Store.I.settings.mode);
            boolean rootReady = rootMode && Bin.rootCopy(c, dst, core) != null;
            boolean exec = rootReady || Bin.probe(dst, core);
            report(cb, true, exec
                    ? core + " 就绪：" + Bin.version(c, core)
                    : core + " 已下载 " + (dst.length() >> 20) + "MB；普通模式不能从应用目录执行，"
                    + "切到 ROOT 模式会自动复制到 /data/local/tmp 运行。");
        } catch (Exception e) {
            report(cb, false, e.toString());
        }
    }

    private static byte[] entry(byte[] zip, String core) {
        try {
            ZipInputStream z = new ZipInputStream(new java.io.ByteArrayInputStream(zip));
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                String nm = e.getName();
                String base = nm.contains("/") ? nm.substring(nm.lastIndexOf('/') + 1) : nm;
                boolean hit = base.equals(core) || base.equals(core + ".exe") || base.equals("lib" + core + ".so");
                if (!hit) continue;
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = z.read(buf)) > 0) b.write(buf, 0, n);
                return b.toByteArray();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static void report(final Cb cb, final boolean ok, final String msg) {
        if (cb != null) cb.onDone(ok, msg);
    }
}
