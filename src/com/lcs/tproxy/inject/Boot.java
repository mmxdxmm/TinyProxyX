package com.lcs.tproxy.inject;

import com.lcs.tproxy.model.Store;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * 自定义 bootstrap DNS：连接建立时先向它解析域名，结果缓存到断开为止。
 *
 * 两种模式（都直连用户填的 IP，不经过 xray、不经过系统 DNS）：
 *   明文 plain  —— 问 ip:port（默认 53）。UDP 超时或被截断就换 TCP 再问一次。
 *   加密 secure —— 端口 443 走 DoH（POST /dns-query），853 走 DoT。
 *                  证书按 SNI 校验，所以加密模式必须填 SNI。
 *
 * 生命周期由 Engine 控制：start 时 begin() 清空缓存，stop 时 clear()。
 * 期间同一个域名只查一次；节点域名、注入网关域名、解析器域名都走这里。
 */
public final class Boot {

    public static final String PLAIN = "plain";
    public static final String SECURE = "secure";

    private static volatile boolean enabled;
    private static volatile String mode = PLAIN;
    private static volatile String ip = "";
    private static volatile int port;
    private static volatile String sni = "";

    /** 会话缓存：host -> ip，断开连接时整张清掉 */
    private static final Map<String, String> session =
            Collections.synchronizedMap(new LinkedHashMap<String, String>());

    private Boot() {
    }

    /* ------------------------------------------------------------- lifecycle */

    public static synchronized void begin(Store.Settings s) {
        mode = SECURE.equals(s.bootMode) ? SECURE : PLAIN;
        ip = s.bootIp == null ? "" : s.bootIp.trim();
        /* 开着开关却没填地址时退回阿里 223.5.5.5：全局 DNS 默认写域名，
         * bootstrap 就是那条"启动时钉 IP"的路，不能因为输入框空着就整条失效。 */
        if (ip.length() == 0 && s.bootEnabled) ip = "223.5.5.5";
        port = s.bootPort;
        sni = s.bootSni == null ? "" : s.bootSni.trim();
        enabled = s.bootEnabled && ip.length() > 0;
        session.clear();
    }

    public static void clear() {
        session.clear();
    }

    public static boolean enabled() {
        return enabled;
    }

    public static String mode() {
        return mode;
    }

    public static String server() {
        return ip;
    }

    public static int port() {
        return port;
    }

    public static String sni() {
        return sni;
    }

    /** 一行描述，写进启动日志 */
    public static String describe() {
        if (!enabled) return "未启用";
        String p = port > 0 ? String.valueOf(port)
                : (SECURE.equals(mode) ? "443" : "53");
        if (PLAIN.equals(mode)) return ip + ":" + p + " 明文";
        return ip + ":" + p + (port == 853 ? " DoT" : " DoH") + (sni.length() > 0 ? " SNI=" + sni : "");
    }

    /** 当前缓存快照（只读副本），给界面和 dns.hosts 用 */
    public static Map<String, String> snapshot() {
        synchronized (session) {
            return new LinkedHashMap<String, String>(session);
        }
    }

    public static String cached(String host) {
        return host == null ? null : session.get(host);
    }

    /* ---------------------------------------------------------------- lookup */

    /** 会话内解析：命中缓存直接返回；未启用返回 null，交给调用方原有通道。 */
    public static String resolve(String host) {
        if (host == null || host.length() == 0) return null;
        if (HttpDns.isIp(host)) return host.trim();
        String hit = session.get(host);
        if (hit != null) return hit;
        if (!enabled) return null;
        String got = query(host, mode, ip, port, sni);
        if (got != null) session.put(host, got);
        return got;
    }

    /** 不读也不写缓存的一次查询，给「测试解析」用 */
    public static String test(String host, String m, String server, int p, String s) {
        if (host == null || host.trim().length() == 0) return null;
        if (server == null || server.trim().length() == 0) return null;
        return query(host.trim(), SECURE.equals(m) ? SECURE : PLAIN,
                server.trim(), p, s == null ? "" : s.trim());
    }

    private static String query(String host, String m, String server, int p, String s) {
        try {
            if (PLAIN.equals(m)) return plain(host, server, p > 0 ? p : 53);
            int prt = p > 0 ? p : 443;
            return prt == 853 ? dot(host, server, prt, s) : doh(host, server, prt, s, "/dns-query");
        } catch (Exception e) {
            return null;
        }
    }

    /* ---------------------------------------------------------------- plain */

    private static String plain(String host, String server, int port) {
        /* 先 UDP 把 A / AAAA 都问一遍；两条都没有再换 TCP —— 有些网络只放 TCP/53。
         * 只有两个 qtype，直接展开，不再为两次查询建一个数组和两层循环。 */
        String a = udp(host, Dns.A, server, port);
        if (a != null) return a;
        a = udp(host, Dns.AAAA, server, port);
        if (a != null) return a;
        try {
            a = tcp(host, Dns.A, server, port);
            if (a != null) return a;
        } catch (Exception ignored) {
        }
        try {
            return tcp(host, Dns.AAAA, server, port);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String udp(String host, int type, String server, int port) {
        DatagramSocket ds = null;
        try {
            byte[] q = Dns.query(host, type);
            ds = new DatagramSocket();
            ds.setSoTimeout(3000);
            InetAddress to = InetAddress.getByName(server);
            ds.send(new DatagramPacket(q, q.length, to, port));
            byte[] buf = new byte[1500];
            DatagramPacket rp = new DatagramPacket(buf, buf.length);
            ds.receive(rp);
            byte[] resp = new byte[rp.getLength()];
            System.arraycopy(rp.getData(), rp.getOffset(), resp, 0, rp.getLength());
            /* TC 置位说明答案被截断，交给 TCP 重问 */
            if (resp.length > 2 && (resp[2] & 0x02) != 0) return null;
            return type == Dns.AAAA ? Dns.firstAAAA(resp) : Dns.firstA(resp);
        } catch (Exception e) {
            return null;
        } finally {
            if (ds != null) ds.close();
        }
    }

    private static String tcp(String host, int type, String server, int port) throws Exception {
        byte[] q = Dns.query(host, type);
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(server, port), 4000);
            s.setSoTimeout(4000);
            OutputStream out = s.getOutputStream();
            out.write((q.length >> 8) & 0xFF);
            out.write(q.length & 0xFF);
            out.write(q);
            out.flush();
            InputStream in = s.getInputStream();
            int hi = in.read();
            int lo = in.read();
            if (hi < 0 || lo < 0) return null;
            byte[] resp = readFully(in, (hi << 8) | lo);
            if (resp == null) return null;
            return type == Dns.AAAA ? Dns.firstAAAA(resp) : Dns.firstA(resp);
        } finally {
            s.close();
        }
    }

    /* --------------------------------------------------------------- secure */

    private static String dot(String host, String server, int port, String sni) throws Exception {
        String a = dotOne(host, Dns.A, server, port, sni);
        if (a != null) return a;
        return dotOne(host, Dns.AAAA, server, port, sni);
    }

    private static String dotOne(String host, int type, String server, int port, String sni) throws Exception {
        byte[] q = Dns.query(host, type);
        SSLSocket s = tls(server, port, sni);
        try {
            OutputStream out = s.getOutputStream();
            out.write((q.length >> 8) & 0xFF);
            out.write(q.length & 0xFF);
            out.write(q);
            out.flush();
            InputStream in = s.getInputStream();
            int hi = in.read();
            int lo = in.read();
            if (hi < 0 || lo < 0) return null;
            byte[] resp = readFully(in, (hi << 8) | lo);
            if (resp == null) return null;
            return type == Dns.AAAA ? Dns.firstAAAA(resp) : Dns.firstA(resp);
        } finally {
            s.close();
        }
    }

    /** DoH：直连 ip:port，TLS 用 SNI 校验证书，POST 一条 application/dns-message。 */
    public static String doh(String host, String server, int port, String sni, String path) throws Exception {
        String a = dohOne(host, Dns.A, server, port, sni, path);
        if (a != null) return a;
        return dohOne(host, Dns.AAAA, server, port, sni, path);
    }

    private static String dohOne(String host, int type, String server, int port, String sni, String path) throws Exception {
        byte[] q = Dns.query(host, type);
        String p = path == null || path.length() == 0 ? "/dns-query" : path;
        if (!p.startsWith("/")) p = "/" + p;
        String hostHdr = sni != null && sni.length() > 0 ? sni : server;
        SSLSocket s = tls(server, port, sni);
        try {
            OutputStream out = s.getOutputStream();
            String head = "POST " + p + " HTTP/1.1\r\n"
                    + "Host: " + hostHdr + "\r\n"
                    + "Accept: application/dns-message\r\n"
                    + "Content-Type: application/dns-message\r\n"
                    + "Content-Length: " + q.length + "\r\n"
                    + "Connection: close\r\n\r\n";
            out.write(head.getBytes(StandardCharsets.ISO_8859_1));
            out.write(q);
            out.flush();

            InputStream in = s.getInputStream();
            String status = line(in);
            if (status == null) return null;
            int code = 0;
            String[] parts = status.split(" ");
            if (parts.length > 1) {
                try {
                    code = Integer.parseInt(parts[1].trim());
                } catch (Exception ignored) {
                }
            }
            HashMap<String, String> h = new HashMap<String, String>();
            String l;
            while ((l = line(in)) != null && l.length() > 0) {
                int c = l.indexOf(':');
                if (c > 0) h.put(l.substring(0, c).trim().toLowerCase(), l.substring(c + 1).trim());
            }
            if (code != 200) return null;
            byte[] body;
            String te = h.get("transfer-encoding");
            if (te != null && te.toLowerCase().contains("chunked")) {
                body = chunked(in);
            } else {
                String cl = h.get("content-length");
                body = cl == null ? readAll(in) : readFully(in, Integer.parseInt(cl.trim()));
            }
            return body == null ? null : (type == Dns.AAAA ? Dns.firstAAAA(body) : Dns.firstA(body));
        } finally {
            s.close();
        }
    }

    /** 裸 socket 连 IP，再用 SNI 当 peer host 做证书校验。 */
    private static SSLSocket tls(String server, int port, String sni) throws Exception {
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(server, port), 4000);
        raw.setSoTimeout(5000);
        String peer = sni != null && sni.length() > 0 ? sni : server;
        SSLSocket s = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                .createSocket(raw, peer, port, true);
        SSLParameters sp = s.getSSLParameters();
        if (sni != null && sni.length() > 0 && !HttpDns.isIp(sni)) {
            sp.setServerNames(Collections.singletonList(new SNIHostName(sni)));
        }
        sp.setEndpointIdentificationAlgorithm("HTTPS");
        s.setSSLParameters(sp);
        s.startHandshake();
        return s;
    }

    /* ----------------------------------------------------------------- wire */

    private static String line(InputStream in) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > 8192) break;
        }
        if (c < 0 && b.size() == 0) return null;
        return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    private static byte[] chunked(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            String size = line(in);
            if (size == null) break;
            int sc = size.indexOf(';');
            if (sc >= 0) size = size.substring(0, sc);
            int n;
            try {
                n = Integer.parseInt(size.trim(), 16);
            } catch (Exception e) {
                break;
            }
            if (n <= 0) break;
            byte[] b = readFully(in, n);
            if (b == null) break;
            out.write(b, 0, b.length);
            line(in);
        }
        return out.toByteArray();
    }

    private static byte[] readFully(InputStream in, int n) throws Exception {
        if (n <= 0) return new byte[0];
        byte[] b = new byte[n];
        int got = 0;
        while (got < n) {
            int r = in.read(b, got, n - got);
            if (r <= 0) return got == 0 ? null : java.util.Arrays.copyOf(b, got);
            got += r;
        }
        return b;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] b = new byte[1024];
        int n;
        while ((n = in.read(b)) > 0) out.write(b, 0, n);
        return out.toByteArray();
    }
}
