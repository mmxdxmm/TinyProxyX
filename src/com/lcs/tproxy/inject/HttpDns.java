package com.lcs.tproxy.inject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import com.lcs.tproxy.model.Store;

import java.util.HashMap;

/** HTTPDNS / DoH resolver, plus an optional local UDP DNS front end.
 *  Netease-style:  http://119.29.29.29/d?dn=example.com
 *  DoH style:      https://doh.pub/dns-query  (application/dns-message POST) */
public class HttpDns {

    private static final int TTL_MS = 60_000;

    /** 一条缓存：IP + 写入时刻。原来拆成 cache/ttl 两张表，每次命中要查两次、锁两次。 */
    private static final class Hit {
        final byte[] ip;
        final long at;

        Hit(String s, long at) {
            this.ip = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            this.at = at;
        }
    }

    private final HashMap<String, Hit> cache = new HashMap<String, Hit>();

    public String url = "";
    /** http | https | tcp | udp */
    public String mode = "http";
    public String plainDns = "";
    public int plainPort = 53;
    /** block | proxy | direct; proxy is not implemented for the injector bootstrap. */
    public String policy = com.lcs.tproxy.model.Profile.DNS_PROXY;
    private DatagramSocket server;

    public void configure(Ini c) {
        configure(c, com.lcs.tproxy.model.Profile.DNS_PROXY);
    }

    public void configure(Ini c, String policy) {
        this.policy = policy;
        mode = c.dnsTcp == null ? "http" : c.dnsTcp.trim().toLowerCase();
        url = c.dnsUrl == null ? "" : c.dnsUrl.trim();
        plainDns = c.dnsIp == null ? "" : c.dnsIp.trim();
        plainPort = c.dnsPort;
        /* 节点里没写 dns_* 时，继承「设置 → DNS」的全局配置：
         * 服务器只放行 DoH 的场景，就是靠这条让注入代理也能解析。 */
        Store.Settings g = Store.I.settings;
        boolean empty = url.length() == 0 && plainDns.length() == 0;
        if (empty && g.dnsEnabled) {
            String r = g.dnsRemote == null ? "" : g.dnsRemote.trim();
            String d = g.dnsDomestic == null ? "" : g.dnsDomestic.trim();
            if (r.length() > 0) applyAddress(r);
            else if (d.length() > 0) applyAddress(d);
        }
        startServer(c.dnsListenPort);
    }

    /** accept the four forms the DNS screen offers: 8.8.8.8 / tcp:// / tls:// / https:// */
    private void applyAddress(String raw) {
        String s = raw.trim();
        if (s.startsWith("tcp://")) {
            plainDns = hostOf(s.substring(6));
            plainPort = portOf(s.substring(6), 53);
            mode = "tcp";
            url = "";
        } else if (s.startsWith("tls://")) {
            plainDns = hostOf(s.substring(6));
            plainPort = portOf(s.substring(6), 853);
            mode = "tls";
            url = "";
        } else if (s.startsWith("https://") || s.startsWith("http://")) {
            url = s;
            mode = "https";
        } else {
            plainDns = hostOf(s);
            plainPort = portOf(s, 53);
            mode = "udp";
            url = "";
        }
    }

    private static String hostOf(String a) {
        String s = a.trim();
        if (s.startsWith("[")) {
            int close = s.indexOf(']');
            if (close > 0) return s.substring(1, close);
        }
        int c = s.lastIndexOf(':');
        /* 只有一个冒号才是 host:port；v6 字面量里的冒号不能当分隔符 */
        if (c > 0 && s.indexOf(':') == c) return s.substring(0, c);
        return s;
    }

    private static int portOf(String a, int def) {
        String s = a.trim();
        int close = s.startsWith("[") ? s.indexOf(']') : -1;
        if (close > 0) {
            if (close + 1 < s.length() && s.charAt(close + 1) == ':') {
                try {
                    return Integer.parseInt(s.substring(close + 2).trim());
                } catch (Exception e) {
                    return def;
                }
            }
            return def;
        }
        int c = s.lastIndexOf(':');
        if (c > 0 && s.indexOf(':') == c) {
            try {
                return Integer.parseInt(s.substring(c + 1).trim());
            } catch (Exception e) {
                return def;
            }
        }
        return def;
    }

    public boolean doh() {
        String u = url.toLowerCase();
        return u.contains("dns-query") || u.startsWith("https://");
    }

    /** Resolve to an IPv4 literal, or null. */
    public String resolve(String host) {
        if (host == null || host.length() == 0) return null;
        if (isIp(host)) return host.trim();
        /* 自定义 bootstrap 优先：一次解析缓存到断开连接，不碰系统 DNS */
        String boot = Boot.resolve(host);
        if (boot != null) return boot;
        long now = System.currentTimeMillis();
        synchronized (cache) {
            Hit hit = cache.get(host);
            if (hit != null && now - hit.at < TTL_MS) {
                return new String(hit.ip, java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        if (com.lcs.tproxy.model.Profile.DNS_BLOCK.equals(policy)) return null;
        /* The injector's bootstrap resolver cannot traverse its own first hop
         * (a domain gateway would recurse). If the user explicitly configured
         * dns_url / dns_ip, use that resolver; otherwise proxy mode fails closed.
         * Only explicit direct policy may fall back to the system resolver. */
        boolean configured = url.length() > 0 || plainDns.length() > 0;
        boolean direct = com.lcs.tproxy.model.Profile.DNS_DIRECT.equals(policy);
        if (!direct && !configured) return null;
        String ip = query(host);
        if (ip == null && direct) ip = viaSystem(host);
        if (ip != null) {
            synchronized (cache) {
                cache.put(host, new Hit(ip, now));
            }
        }
        return ip;
    }

    private String query(String host) {
        /* A 空就再问 AAAA：v6-only 的域名只有 AAAA，只问 A 的路径永远拿不到地址。 */
        for (int type : new int[]{Dns.A, Dns.AAAA}) {
            String ip = queryType(host, type);
            if (ip != null) return ip;
        }
        return null;
    }

    private static final int M_HTTP = 0;
    private static final int M_TCP = 1;
    private static final int M_UDP = 2;
    private static final int M_TLS = 3;

    /** dns_tcp 的四种取值：tcp / tls 只靠第二个字符区分，其余按 HTTPDNS。 */
    private int modeId() {
        if (mode == null || mode.length() == 0) return M_HTTP;
        char c = mode.charAt(0);
        if (c == 't') return mode.length() > 1 && mode.charAt(1) == 'l' ? M_TLS : M_TCP;
        if (c == 'u') return M_UDP;
        return M_HTTP;
    }

    private String queryType(String host, int type) {
        try {
            /* tcp  -> DNS over TCP (RFC 1035 framing) against dns_ip:dns_port
             * udp  -> plain UDP
             * tls  -> DoT
             * otherwise -> HTTPDNS / DoH through dns_url */
            switch (modeId()) {
                case M_TCP:
                    return queryPlain(host, type, true);
                case M_UDP:
                    return queryPlain(host, type, false);
                case M_TLS:
                    return queryDot(host, type);
                default:
                    if (url.length() == 0) return queryPlain(host, type, false);
                    return doh() ? queryDoh(host, type) : queryHttp(host);
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static String pick(int type, byte[] resp) {
        return type == Dns.AAAA ? Dns.firstAAAA(resp) : Dns.firstA(resp);
    }

    /** dns_ip 可能写成域名：先过 bootstrap，拿到 IP 再连 */
    private String endpoint() {
        if (plainDns.length() == 0) return plainDns;
        String ip = Boot.resolve(plainDns);
        return ip == null ? plainDns : ip;
    }

    /** DNS over TLS: same 2-byte framing, wrapped in a TLS session. */
    private String queryDot(String host, int type) throws Exception {
        byte[] q = Dns.query(host, type);
        javax.net.ssl.SSLSocket s = (javax.net.ssl.SSLSocket)
                javax.net.ssl.SSLSocketFactory.getDefault().createSocket();
        s.connect(new java.net.InetSocketAddress(endpoint(), plainPort == 53 ? 853 : plainPort), 5000);
        s.setSoTimeout(5000);
        s.startHandshake();
        OutputStream out = s.getOutputStream();
        out.write((q.length >> 8) & 0xFF);
        out.write(q.length & 0xFF);
        out.write(q);
        out.flush();
        InputStream in = s.getInputStream();
        int hi = in.read();
        int lo = in.read();
        if (hi < 0 || lo < 0) {
            s.close();
            return null;
        }
        int len = (hi << 8) | lo;
        byte[] resp = new byte[len];
        int got = 0;
        while (got < len) {
            int n = in.read(resp, got, len - got);
            if (n <= 0) break;
            got += n;
        }
        s.close();
        return Dns.firstA(resp);
    }

    /** UDP-over-TCP style DNS: 2-byte length prefix, exactly what every resolver speaks. */
    private String queryPlain(String host, int type, boolean tcp) throws Exception {
        byte[] q = Dns.query(host, type);
        if (plainDns.length() == 0) {
            return InetAddress.getByName(host).getHostAddress();
        }
        if (tcp) {
            Socket s = new Socket();
            s.connect(new java.net.InetSocketAddress(endpoint(), plainPort == 53 ? 53 : plainPort), 4000);
            s.setSoTimeout(4000);
            OutputStream out = s.getOutputStream();
            out.write((q.length >> 8) & 0xFF);
            out.write(q.length & 0xFF);
            out.write(q);
            out.flush();
            InputStream in = s.getInputStream();
            int hi = in.read();
            int lo = in.read();
            if (hi < 0 || lo < 0) {
                s.close();
                return null;
            }
            int len = (hi << 8) | lo;
            byte[] resp = new byte[len];
            int got = 0;
            while (got < len) {
                int n = in.read(resp, got, len - got);
                if (n <= 0) break;
                got += n;
            }
            s.close();
            return pick(type, resp);
        }
        java.net.DatagramSocket ds = new java.net.DatagramSocket();
        ds.setSoTimeout(4000);
        java.net.InetAddress to = InetAddress.getByName(endpoint());
        ds.send(new DatagramPacket(q, q.length, to, plainPort));
        byte[] buf = new byte[1500];
        DatagramPacket rp = new DatagramPacket(buf, buf.length);
        ds.receive(rp);
        ds.close();
        byte[] resp = new byte[rp.getLength()];
        System.arraycopy(rp.getData(), rp.getOffset(), resp, 0, rp.getLength());
        return Dns.firstA(resp);
    }

    /** 明文 HTTPDNS 不校验证书：URL 里的域名直接换成 bootstrap 给的 IP */
    private static String bootUrl(String u) {
        if (!Boot.enabled()) return u;
        try {
            URL a = new URL(u);
            if (isIp(a.getHost())) return u;
            String ip = Boot.resolve(a.getHost());
            if (ip == null) return u;
            return new URL(a.getProtocol(), ip, a.getPort(), a.getFile()).toString();
        } catch (Exception e) {
            return u;
        }
    }

    private String queryHttp(String host) throws Exception {
        String u = url.contains("{domain}") ? url.replace("{domain}", host)
                : url + (url.contains("?") ? "&" : "?") + "dn=" + host;
        HttpURLConnection c = (HttpURLConnection) new URL(bootUrl(u)).openConnection();
        c.setConnectTimeout(4000);
        c.setReadTimeout(4000);
        c.setRequestProperty("User-Agent", "TinyProxyX");
        InputStream in = c.getInputStream();
        byte[] b = new byte[2048];
        int n = in.read(b);
        in.close();
        String body = new String(b, 0, Math.max(0, n), "UTF-8");
        return firstV4(body);
    }

    private String queryDoh(String host, int type) throws Exception {
        URL a = new URL(url);
        /* dns_url 写的是域名时，先过 bootstrap 拿 IP，再按 SNI 校验证书连过去 */
        if (Boot.enabled() && !isIp(a.getHost())) {
            String ip = Boot.resolve(a.getHost());
            if (ip != null) {
                int p = a.getPort() > 0 ? a.getPort() : 443;
                return Boot.doh(host, ip, p, a.getHost(), a.getFile());
            }
        }
        byte[] q = Dns.query(host, type);
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(5000);
        c.setReadTimeout(5000);
        c.setDoOutput(true);
        c.setRequestMethod("POST");
        c.setRequestProperty("Content-Type", "application/dns-message");
        c.setRequestProperty("Accept", "application/dns-message");
        OutputStream out = c.getOutputStream();
        out.write(q);
        out.flush();
        out.close();
        InputStream in = c.getInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] b = new byte[1024];
        int n;
        while ((n = in.read(b)) > 0) bos.write(b, 0, n);
        in.close();
        return pick(type, bos.toByteArray());
    }

    private String viaSystem(String host) {
        if (plainDns.length() == 0) {
            try {
                return InetAddress.getByName(host).getHostAddress();
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    /** resolve, or hand back the literal we were given (used by the injector). */
    public String resolveOr(String host, String fallback) {
        String ip = resolve(host);
        if (ip != null) return ip;
        return com.lcs.tproxy.model.Profile.DNS_DIRECT.equals(policy) ? fallback : null;
    }

    public static String firstV4(String s) {
        /* 手写扫描代替正则：HTTPDNS 一行应答里可能有一堆数字，正则每次都要建 matcher。 */
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) < '0' || s.charAt(i) > '9') continue;
            /* 左边界：前面还是字母/数字/下划线时，这段数字不是一个独立的地址。
             * 原正则靠 \b 做到这一点，手写扫描也得补上。 */
            if (i > 0 && v4Word(s.charAt(i - 1))) continue;
            int end = v4End(s, i);
            if (end > i && !v4Tail(s, end)) return s.substring(i, end);
        }
        return null;
    }

    private static boolean v4Word(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    }

    /** 边界判断：4 后面再跟字母/数字/点，说明这段不是独立的 IPv4。 */
    private static boolean v4Tail(String s, int end) {
        if (end >= s.length()) return false;
        char c = s.charAt(end);
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.';
    }

    /** 从 from 开始若是一段合法 IPv4，返回结束下标（不含），否则 -1。 */
    private static int v4End(String s, int from) {
        int p = from;
        for (int octet = 0; octet < 4; octet++) {
            int v = 0;
            int digits = 0;
            while (p < s.length()) {
                char c = s.charAt(p);
                if (c < '0' || c > '9') break;
                v = v * 10 + (c - '0');
                digits++;
                p++;
                if (digits > 3) return -1;
            }
            if (digits == 0 || v > 255) return -1;
            if (octet == 3) return p;
            if (p >= s.length() || s.charAt(p) != '.') return -1;
            p++;
        }
        return -1;
    }

    public static boolean isV4(String s) {
        int n = s.length();
        if (n < 7 || n > 15) return false;
        int octet = v4End(s, 0);
        return octet == n;
    }

    /** v4 或 v6 字面量（v6 只判形状，不做完整校验）。 */
    /** v6 只判形状，不做完整校验；字符集查表，不再每字符四连比较。 */
    private static final boolean[] V6_CHAR = new boolean[128];

    static {
        for (int c = '0'; c <= '9'; c++) V6_CHAR[c] = true;
        for (int c = 'a'; c <= 'f'; c++) V6_CHAR[c] = true;
        for (int c = 'A'; c <= 'F'; c++) V6_CHAR[c] = true;
        V6_CHAR[':'] = true;
        V6_CHAR['.'] = true;
        V6_CHAR['%'] = true;
    }

    public static boolean isIp(String s) {
        if (s == null) return false;
        String t = s.trim();
        if (isV4(t)) return true;
        int n = t.length();
        if (n < 3 || n > 45 || t.indexOf(':') < 0) return false;
        for (int i = 0; i < n; i++) {
            char c = t.charAt(i);
            if (c >= 128 || !V6_CHAR[c]) return false;
        }
        return true;
    }

    /* ------------------------------------------------------------ udp server */

    public void startServer(final int port) {
        if (port <= 0 || server != null) return;
        new Thread(new Runnable() {
            public void run() {
                try {
                    server = new DatagramSocket(port, InetAddress.getByName("127.0.0.1"));
                    byte[] buf = new byte[1500];
                    while (true) {
                        DatagramPacket p = new DatagramPacket(buf, buf.length);
                        server.receive(p);
                        byte[] req = new byte[p.getLength()];
                        System.arraycopy(p.getData(), p.getOffset(), req, 0, p.getLength());
                        byte[] resp = Dns.answer(req, HttpDns.this);
                        if (resp != null) {
                            server.send(new DatagramPacket(resp, resp.length, p.getAddress(), p.getPort()));
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }).start();
    }

    public void stop() {
        try {
            if (server != null) server.close();
        } catch (Exception ignored) {
        }
        server = null;
    }

    public String describe() {
        return url.length() > 0 ? url : (plainDns.length() > 0 ? plainDns : "系统解析");
    }
}
