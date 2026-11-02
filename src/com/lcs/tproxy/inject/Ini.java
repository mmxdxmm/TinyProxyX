package com.lcs.tproxy.inject;

import java.util.HashMap;
import java.util.Map;

/** Legacy TinyProxy config (Socks5ProxyConfig in 3.2.7): the key=value; ini dialect.
 *  Keys are read by name into a small map — the old fixed slot array made deleting a key
 *  shift every following index, which is exactly how a parser silently starts reading
 *  http_port into the dns field. */
public class Ini {

    public String raw = "";
    public int listenPort = 65080;
    public String localIp = "127.0.0.1";

    public String httpIp = "";
    public int httpPort = 80;
    public String httpFirst = "";
    public String httpDel = "";

    public String httpsIp = "";
    public int httpsPort = 443;
    public String httpsFirst = "";
    public String httpsDel = "";

    public boolean httpOn = true;
    public boolean httpsOn = true;
    /** http_direct=on：明文 HTTP 直连目标，不经过网关（原版 Socks5ProxyConfig.isHttpDirect 写死 false） */
    public boolean httpDirect = false;
    /** https_direct=on：CONNECT 直连目标，不经过网关（原版写死 false） */
    public boolean httpsDirect = false;
    /** 界面语义：是否注入模板 = 非直连。真值由 parse 从 http_direct/https_direct 推出来 */
    public boolean httpDispose = true;
    public boolean httpsDispose = true;
    /** 旧字段，已经没有「明文塞进 https 网关」这种接管了，保留只为读老配置 */
    public boolean httpFallbackHttps = false;
    /** 模板被网关拒绝时是否自动改用普通 CONNECT；默认关：让配置错误暴露出来 */
    public boolean injectFallback = false;

    /** http | https | tcp | udp  (原版 dns_tcp) */
    public String dnsTcp = "http";
    public String dnsUrl = "";
    public String dnsIp = "";
    public int dnsPort = 53;
    public int dnsListenPort = 0;

    public String name = "";
    public String apn = "";
    public String v2rayDomain = "";
    public String confModel = "";

    /** parse; comment char # and ; terminator, values may be quoted */
    public static Ini parse(String text) {
        Ini c = new Ini();
        c.raw = text == null ? "" : text;
        /* 单趟扫描：不再 split("[\\r\\n]+")（每次都要编正则、还要建一个行数组），
         * 也不再为每行 substring 两次。行边界、# 注释、= 分隔用三个下标一起认。 */
        Map<String, String> kv = new HashMap<String, String>(16);
        int n = c.raw.length();
        int i = 0;
        while (i < n) {
            char ch = c.raw.charAt(i);
            if (ch == '\r' || ch == '\n') {
                i++;
                continue;
            }
            int end = i;
            int hash = -1;
            int eq = -1;
            while (end < n) {
                char d = c.raw.charAt(end);
                if (d == '\r' || d == '\n') break;
                if (d == '#') {
                    if (hash < 0) hash = end;
                } else if (d == '=' && eq < 0 && hash < 0) {
                    eq = end;
                }
                end++;
            }
            int stop = hash < 0 ? end : hash;
            if (eq > i) {
                int ks = i;
                int ke = eq;
                while (ks < ke && c.raw.charAt(ks) <= ' ') ks++;
                while (ke > ks && c.raw.charAt(ke - 1) <= ' ') ke--;
                if (ke > ks) {
                    int vs = eq + 1;
                    int ve = stop;
                    while (vs < ve && isTrim(c.raw.charAt(vs))) vs++;
                    while (ve > vs && isTrim(c.raw.charAt(ve - 1))) ve--;
                    kv.put(c.raw.substring(ks, ke), unescape(c.raw.substring(vs, ve)));
                }
            }
            i = end;
        }
        c.listenPort = num(v(kv, "listen_port"), 65080);
        c.localIp = str(v(kv, "local_ip"), "127.0.0.1");
        c.httpIp = str(v(kv, "http_ip"), "");
        c.httpPort = num(v(kv, "http_port"), 80);
        c.httpFirst = str(v(kv, "http_first"), "");
        c.httpDel = str(v(kv, "http_del"), str(v(kv, "http_delate"), ""));
        c.httpOn = on(v(kv, "http_others"), true);
        c.httpDirect = on(v(kv, "http_direct"), false);
        c.httpDispose = !c.httpDirect;
        c.httpsIp = str(v(kv, "https_ip"), "");
        c.httpsPort = num(v(kv, "https_port"), 443);
        c.httpsFirst = str(v(kv, "https_first"), "");
        c.httpsDel = str(v(kv, "https_del"), str(v(kv, "https_delate"), ""));
        c.httpsOn = on(v(kv, "https_connect"), true);
        c.httpsDirect = on(v(kv, "https_direct"), false);
        c.httpsDispose = !c.httpsDirect;
        c.httpFallbackHttps = on(v(kv, "http_fallback"), false);
        c.injectFallback = on(v(kv, "inject_fallback"), false);
        c.dnsTcp = str(v(kv, "dns_tcp"), "http");
        c.dnsUrl = str(v(kv, "dns_url"), "");
        c.dnsIp = str(v(kv, "dns_ip"), "");
        c.dnsPort = num(v(kv, "dns_port"), 53);
        c.dnsListenPort = num(v(kv, "dns_listen_port"), 0);
        c.name = str(v(kv, "name"), str(v(kv, "remarks"), ""));
        c.apn = str(v(kv, "apn"), "");
        c.v2rayDomain = str(v(kv, "v2ray_domain"), "");
        c.confModel = str(v(kv, "conf_model"), "");
        return c;
    }

    private static String v(Map<String, String> kv, String key) {
        return kv.get(key);
    }

    /** 值两侧要去掉的字符。用 switch 让 javac 生成跳转表：一次间接跳转，没有 7 次比较。 */
    private static boolean isTrim(char c) {
        switch (c) {
            case ' ':
            case '\t':
            case '"':
            case '\'':
            case ';':
            case '\r':
            case '\n':
                return true;
            default:
                return false;
        }
    }

    public static String unescape(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                b.append(c);
                continue;
            }
            char n = s.charAt(++i);
            switch (n) {
                case 'r': b.append('\r'); break;
                case 'n': b.append('\n'); break;
                case 't': b.append('\t'); break;
                default: b.append(n);
            }
        }
        return b.toString();
    }

    public static String escape(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\r': b.append("\\r"); break;
                case '\n': b.append("\\n"); break;
                case '\t': b.append("\\t"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }

    private static String str(String v, String def) {
        return v == null || v.length() == 0 ? def : v;
    }

    private static int num(String v, int def) {
        try {
            return v == null ? def : Integer.parseInt(v.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static boolean on(String v, boolean def) {
        if (v == null || v.length() == 0) return def;
        String s = v.trim().toLowerCase();
        return s.equals("on") || s.equals("true") || s.equals("1") || s.equals("yes");
    }

    public String dump() {
        StringBuilder b = new StringBuilder();
        b.append("listen_port=").append(listenPort).append(";\n");
        b.append("local_ip=").append(localIp).append(";\n\n");
        b.append("http_others=").append(httpOn ? "on" : "off").append(";\n");
        b.append("http_direct=").append(httpDirect ? "on" : "off").append(";\n");
        b.append("http_ip=").append(httpIp).append(";\n");
        b.append("http_port=").append(httpPort).append(";\n");
        b.append("http_del=\"").append(httpDel).append("\";\n");
        b.append("http_first=\"").append(escape(httpFirst)).append("\";\n\n");
        b.append("https_connect=").append(httpsOn ? "on" : "off").append(";\n");
        b.append("https_direct=").append(httpsDirect ? "on" : "off").append(";\n");
        b.append("https_ip=").append(httpsIp).append(";\n");
        b.append("https_port=").append(httpsPort).append(";\n");
        b.append("https_del=\"").append(httpsDel).append("\";\n");
        b.append("https_first=\"").append(escape(httpsFirst)).append("\";\n\n");
        b.append("inject_fallback=").append(injectFallback ? "on" : "off").append(";\n");
        b.append("dns_tcp=").append(dnsTcp).append(";\n");
        if (dnsUrl.length() > 0) b.append("dns_url=\"").append(dnsUrl).append("\";\n");
        if (dnsIp.length() > 0) b.append("dns_ip=").append(dnsIp).append(";\n");
        if (dnsPort > 0 && dnsPort != 53) b.append("dns_port=").append(dnsPort).append(";\n");
        if (dnsListenPort > 0) b.append("dns_listen_port=").append(dnsListenPort).append(";\n");
        if (name.length() > 0) b.append("remarks=").append(name).append(";\n");
        return b.toString();
    }

    public String summary() {
        StringBuilder b = new StringBuilder();
        b.append("HTTP ").append(httpDispose ? "注入" : "直连");
        if (httpIp.length() > 0) b.append(" → ").append(httpIp).append(':').append(httpPort);
        b.append("  ·  HTTPS ").append(httpsDispose ? "注入" : "直连");
        if (httpsIp.length() > 0) b.append(" → ").append(httpsIp).append(':').append(httpsPort);
        return b.toString();
    }

    public boolean hasTemplate() {
        return httpFirst.length() > 0 || httpsFirst.length() > 0;
    }

    /** Neutral example: no carrier bait domain, exactly the shapes the original shipped.
     *  The https default is verbatim from the 3.2.7 dex ("CONNECT [H] HTTP/1.1\r\nHost: [H]\r\n\r\n").
     *  In it [H] expands to host:port (ProxyTask.doConnect builds host0 + ":" + port0), and in the
     *  http template [U] is the raw request target, which is what SocketThreadOutput.httpmod uses. */
    public static Ini defaults() {
        Ini c = new Ini();
        c.httpFirst = "[M] [U] [V]\r\n";
        c.httpsFirst = "CONNECT [H] HTTP/1.1\r\nHost: [H]\r\n\r\n";
        c.httpDel = "Host,X-Online-Host";
        c.httpsDel = "Host,X-Online-Host";
        return c;
    }
}
