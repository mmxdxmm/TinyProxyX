package com.lcs.tproxy.model;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

/** Single-source-of-truth store backed by one json file in filesDir. */
public class Store {

    public static final Store I = new Store();

    public final List<Profile> profiles = new ArrayList<Profile>();
    public String selectedId = "";
    public Settings settings = new Settings();
    private File file;

    public static class Settings {
        /** vpn | root */
        public String mode = "vpn";
        public int socksPort = 10808;
        public int httpPort = 10809;
        public int tproxyPort = 12345;
        public int redirectPort = 12346;
        public boolean allowLan = false;
        public boolean bypassPrivate = true;
        public String coreUrl = "";
        /** 订阅地址，一行一个 */
        public String subUrls = "";
        /* global dns (v2rayNG style): remote/domestic resolvers, 53 hijack */
        public boolean dnsEnabled = false;
        public String dnsRemote = "";
        public String dnsDomestic = "";
        public boolean dnsHijack = true;
        /* 自定义 bootstrap DNS：连接建立时先向它解析所有域名，结果缓存到断开为止。
         * 双模式：明文（UDP，失败转 TCP）/ 加密（443 DoH、853 DoT），都直连填的 IP。
         * 全局 DNS 默认写域名，所以 bootstrap 默认开着、默认用阿里 223.5.5.5。 */
        public boolean bootEnabled = true;
        public String bootMode = "plain";
        public String bootIp = "223.5.5.5";
        public int bootPort = 0;
        public String bootSni = "";
        /** 日志保留条数 */
        public int logLines = 500;
        public String geoUrl = "";
        /** per-core custom download url: xray */
        public java.util.LinkedHashMap<String, String> coreUrls = new java.util.LinkedHashMap<String, String>();
        public boolean preferUpdatedCore = true;
        // root mode
        public boolean rootHotspot = true;
        public boolean rootProxyLocal = true;
        public boolean rootUdp = true;
        /** ip6tables 同步下发，堵住 IPv6 侧漏 */
        public boolean rootIpv6 = true;
        /** 规则已下发但应用没在跑（被杀/崩溃）时，下次启动兜底清理 */
        public boolean rootArmed = false;
        /** v1.4.3 一次性迁移标记：把旧默认「绕过大陆」改成「全部走代理」 */
        public boolean presetMoved = false;
        public List<String> proxyIfs = new ArrayList<String>();
        public List<String> bypassIfs = new ArrayList<String>();
        public List<String> ignoreIfs = new ArrayList<String>();
        public String customCorePath = "";

        public JSONObject toJson() {
            JSONObject o = new JSONObject();
            try {
                o.put("mode", mode);
                o.put("socksPort", socksPort);
                o.put("httpPort", httpPort);
                o.put("tproxyPort", tproxyPort);
                o.put("redirectPort", redirectPort);
                o.put("allowLan", allowLan);
                o.put("bypassPrivate", bypassPrivate);
                o.put("coreUrl", coreUrl);
                o.put("subUrls", subUrls);
                o.put("dnsEnabled", dnsEnabled);
                o.put("dnsRemote", dnsRemote);
                o.put("dnsDomestic", dnsDomestic);
                o.put("dnsHijack", dnsHijack);
                o.put("bootEnabled", bootEnabled);
                o.put("bootMode", bootMode);
                o.put("bootIp", bootIp);
                o.put("bootPort", bootPort);
                o.put("bootSni", bootSni);
                o.put("logLines", logLines);
                o.put("geoUrl", geoUrl);
                JSONObject urls = new JSONObject();
                for (java.util.Map.Entry<String, String> e : coreUrls.entrySet()) {
                    urls.put(e.getKey(), e.getValue());
                }
                o.put("coreUrls", urls);
                o.put("preferUpdatedCore", preferUpdatedCore);
                o.put("rootHotspot", rootHotspot);
                o.put("rootProxyLocal", rootProxyLocal);
                o.put("rootUdp", rootUdp);
                o.put("rootIpv6", rootIpv6);
                o.put("rootArmed", rootArmed);
            o.put("presetMoved", presetMoved);
                o.put("proxyIfs", new JSONArray(proxyIfs));
                o.put("bypassIfs", new JSONArray(bypassIfs));
                o.put("ignoreIfs", new JSONArray(ignoreIfs));
                o.put("customCorePath", customCorePath);
            } catch (Exception ignored) {
            }
            return o;
        }

        public static Settings fromJson(JSONObject o) {
            Settings s = new Settings();
            s.mode = normalizeMode(o.optString("mode", "vpn"));
            s.socksPort = o.optInt("socksPort", 10808);
            s.httpPort = o.optInt("httpPort", 10809);
            s.tproxyPort = o.optInt("tproxyPort", 12345);
            s.redirectPort = o.optInt("redirectPort", 12346);
            s.allowLan = o.optBoolean("allowLan", false);
            s.bypassPrivate = o.optBoolean("bypassPrivate", true);
            s.coreUrl = o.optString("coreUrl", "");
            s.subUrls = o.optString("subUrls", "");
            s.dnsEnabled = o.optBoolean("dnsEnabled", false);
            s.dnsRemote = o.optString("dnsRemote", "");
            s.dnsDomestic = o.optString("dnsDomestic", "");
            s.dnsHijack = o.optBoolean("dnsHijack", true);
            s.bootEnabled = o.optBoolean("bootEnabled", true);
            s.bootMode = o.optString("bootMode", "plain");
            s.bootIp = o.optString("bootIp", "223.5.5.5");
            s.bootPort = o.optInt("bootPort", 0);
            s.bootSni = o.optString("bootSni", "");
            s.logLines = o.optInt("logLines", 500);
            s.geoUrl = o.optString("geoUrl", "");
            JSONObject urls = o.optJSONObject("coreUrls");
            if (urls != null) {
                java.util.Iterator<String> it = urls.keys();
                while (it.hasNext()) {
                    String k = it.next();
                    s.coreUrls.put(k, urls.optString(k, ""));
                }
            }
            s.preferUpdatedCore = o.optBoolean("preferUpdatedCore", true);
            s.rootHotspot = o.optBoolean("rootHotspot", true);
            s.rootProxyLocal = o.optBoolean("rootProxyLocal", true);
            s.rootUdp = o.optBoolean("rootUdp", true);
            s.rootIpv6 = o.optBoolean("rootIpv6", true);
            s.rootArmed = o.optBoolean("rootArmed", false);
            s.presetMoved = o.optBoolean("presetMoved", false);
            s.proxyIfs = strList(o.optJSONArray("proxyIfs"));
            s.bypassIfs = strList(o.optJSONArray("bypassIfs"));
            s.ignoreIfs = strList(o.optJSONArray("ignoreIfs"));
            s.customCorePath = o.optString("customCorePath", "");
            return s;
        }

        /** 只有 vpn / root 两种。老存档里的 root-redirect 是「只接管 TCP」的旧分支，
         *  1.5.0 起本机与转发都统一走 nat REDIRECT，两个分支合成一个，读进来就地归一。 */
        private static String normalizeMode(String m) {
            return "root-redirect".equals(m) ? "root" : m;
        }

        private static List<String> strList(JSONArray a) {
            List<String> l = new ArrayList<String>();
            if (a != null) for (int i = 0; i < a.length(); i++) l.add(a.optString(i));
            return l;
        }
    }

    public synchronized void load(Context c) {
        file = new File(c.getFilesDir(), "store.json");
        if (!file.exists()) return;
        try {
            byte[] b = new byte[(int) file.length()];
            FileInputStream in = new FileInputStream(file);
            int off = 0;
            while (off < b.length) {
                int n = in.read(b, off, b.length - off);
                if (n <= 0) break;
                off += n;
            }
            in.close();
            JSONObject o = new JSONObject(new String(b, "UTF-8"));
            profiles.clear();
            JSONArray a = o.optJSONArray("profiles");
            if (a != null) for (int i = 0; i < a.length(); i++) profiles.add(Profile.fromJson(a.optJSONObject(i)));
            selectedId = o.optString("selected", "");
            JSONObject s = o.optJSONObject("settings");
            if (s != null) settings = Settings.fromJson(s);
        } catch (Exception ignored) {
        }
        /* 注入节点里那份 UDP 承载节点是复制品：列表被订阅更新或手改过之后，
         * 这里按来源指纹对一次账，过期副本当场换新。 */
        int synced = NodeSync.reconcile();
        /* v1.4.3：旧版本默认预设是「绕过大陆」，改成「全部走代理」。只跑一次，
         * 之后用户自己改回绕过大陆不会被覆盖。 */
        if (!settings.presetMoved) {
            for (Profile p : profiles) {
                if (Profile.P_BYPASS_CN.equals(p.preset)) p.preset = Profile.P_GLOBAL;
            }
            settings.presetMoved = true;
            save();
        } else if (synced > 0) {
            save();
        }
        if (profiles.isEmpty()) seed();
    }

    public synchronized void save() {
        if (file == null) return;
        try {
            JSONObject o = new JSONObject();
            JSONArray a = new JSONArray();
            for (Profile p : profiles) a.put(p.toJson());
            o.put("profiles", a);
            o.put("selected", selectedId);
            o.put("settings", settings.toJson());
            FileOutputStream out = new FileOutputStream(file);
            out.write(o.toString().getBytes("UTF-8"));
            out.flush();
            out.close();
        } catch (Exception ignored) {
        }
    }

    public Profile selected() {
        for (Profile p : profiles) if (p.id.equals(selectedId)) return p;
        return profiles.isEmpty() ? null : profiles.get(0);
    }

    public void select(String id) {
        selectedId = id;
        save();
    }

    public void add(Profile p) {
        profiles.add(0, p);
        selectedId = p.id;
        save();
    }

    public void remove(Profile p) {
        profiles.remove(p);
        if (p.id.equals(selectedId)) selectedId = profiles.isEmpty() ? "" : profiles.get(0).id;
        save();
    }

    private void seed() {
        Profile p = new Profile("示例 · VLESS");
        Node n = new Node(Node.VLESS, "example.com", 443);
        n.name = "example.com";
        n.uuid = "00000000-0000-0000-0000-000000000000";
        n.security = "tls";
        n.sni = "example.com";
        n.fp = "chrome";
        n.net = "ws";
        n.path = "/ray";
        n.hostHdr = "example.com";
        p.chain.add(n);
        profiles.add(p);
        selectedId = p.id;
        save();
    }
}

