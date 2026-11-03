package com.lcs.tproxy.inject;

import com.lcs.tproxy.link.Links;
import com.lcs.tproxy.model.Kinds;
import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.NodeSync;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Rule;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.xray.Conf;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * JVM 侧的回归测试：不依赖 Android 运行时，只跑纯逻辑 + 本机 socket 端到端。
 * 覆盖注入器的六条请求路径、DNS 编解码、链接导入导出、配置生成的全部分支组合，
 * 以及 UDP 承载节点副本的启动对账。
 */
public final class RefactorTest {

    private static int checks;
    private static int failed;

    public static void main(String[] args) throws Exception {
        ini();
        injectParsing();
        injectPaths();
        dnsCodec();
        ipLiterals();
        nodes();
        profiles();
        confProtocols();
        confStreams();
        confAdvanced();
        confChains();
        confRouting();
        links();
        linksAdvanced();
        nodeSync();
        System.out.println();
        System.out.println("checks=" + checks + " failed=" + failed);
        if (failed > 0) System.exit(1);
    }

    /* ------------------------------------------------------------------ asserts */

    private static void ok(boolean cond, String what) {
        checks++;
        if (!cond) {
            failed++;
            System.out.println("FAIL  " + what);
        }
    }

    private static void eq(Object got, Object want, String what) {
        boolean same = got == null ? want == null : got.equals(want);
        checks++;
        if (!same) {
            failed++;
            System.out.println("FAIL  " + what + "  got=" + got + " want=" + want);
        }
    }

    private static void section(String name) {
        System.out.println("== " + name);
    }

    /* -------------------------------------------------------------------- ini */

    private static void ini() {
        section("Ini");
        String text = "listen_port=65081;\n"
                + "http_others=off;\n"
                + "http_direct=on;\n"
                + "http_ip=1.2.3.4;\n"
                + "http_port=8080;\n"
                + "http_first=\"[M] [U] [V]\\r\\nHost: [H]\\r\\n\";\n"
                + "https_ip=gw.example.com;\n"
                + "https_connect=on;\n"
                + "https_first=\"CONNECT [H] HTTP/1.1\\r\\n\";\n"
                + "# comment = ignored\n"
                + "dns_tcp=udp;\n"
                + "dns_ip=223.5.5.5;\n"
                + "remarks=测试节点;\n";
        Ini c = Ini.parse(text);
        eq(c.listenPort, 65081, "listen_port");
        ok(!c.httpOn, "http_others=off");
        ok(c.httpDirect, "http_direct=on");
        eq(c.httpIp, "1.2.3.4", "http_ip");
        eq(c.httpPort, 8080, "http_port");
        eq(c.httpFirst, "[M] [U] [V]\r\nHost: [H]\r\n", "http_first unescape");
        eq(c.httpsIp, "gw.example.com", "https_ip");
        eq(c.dnsTcp, "udp", "dns_tcp");
        eq(c.name, "测试节点", "remarks");
        eq(c.dnsPort, 53, "dns_port default");

        Ini d = Ini.defaults();
        Ini round = Ini.parse(d.dump());
        eq(round.httpFirst, d.httpFirst, "dump/parse http_first");
        eq(round.httpsFirst, d.httpsFirst, "dump/parse https_first");
        eq(round.httpDel, d.httpDel, "dump/parse http_del");
        ok(d.hasTemplate(), "defaults has template");
        eq(Ini.escape("a\r\nb\tc"), "a\\r\\nb\\tc", "escape");
        eq(Ini.unescape("a\\r\\nb\\tc"), "a\r\nb\tc", "unescape");
    }

    /* --------------------------------------------------------- inject parsing */

    private static void injectParsing() {
        section("InjectServer parsing");
        InjectServer.Req r = InjectServer.Req.of(
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: x\r\n\r\n");
        eq(r.method, "CONNECT", "connect method");
        ok(r.tunnel(), "connect tunnel");
        eq(r.host, "example.com", "connect host");
        eq(r.port, 443, "connect port");
        eq(r.hostHeader, "example.com:443", "connect host header");

        r = InjectServer.Req.of("GET http://a.b:8080/x?q=1 HTTP/1.1\r\nhost:  a.b \r\n\r\n");
        eq(r.method, "GET", "get method");
        eq(r.host, "a.b", "absolute host");
        eq(r.port, 8080, "absolute port");
        eq(r.hostHeader, "a.b", "case-insensitive host header");

        r = InjectServer.Req.of("POST /p HTTP/1.1\r\nContent-Length: 3\r\nHost: c.d\r\n\r\n");
        eq(r.host, "c.d", "relative host");
        eq(r.port, 80, "post default port");
        eq(r.version, "HTTP/1.1", "version");

        r = InjectServer.Req.of("FOO /x HTTP/1.1\r\n\r\n");
        eq(r.host, "/x", "unknown method host fallback");
        eq(r.port, 80, "unknown method port");

        eq(InjectServer.render("[M] [U] [V]\r\nHost: [H]\r\n", "GET", "a.b:80", "/x", "HTTP/1.1"),
                "GET /x HTTP/1.1\r\nHost: a.b:80\r\n\r\n", "render basic");
        eq(InjectServer.render("[method] [uri] [version] [host]", "CONNECT", "h:443", "", "HTTP/1.1"),
                "CONNECT  HTTP/1.1 h:443\r\n\r\n", "render aliases");
        eq(InjectServer.render("x [X] y", "GET", "h", "/", "HTTP/1.1"), "x [X] y\r\n\r\n", "render unknown token");
        eq(InjectServer.render("a\r\n\r\n\r\nb", "GET", "h", "/", "HTTP/1.1"), "a\r\nb\r\n\r\n", "render blank collapse");
        eq(InjectServer.sealed("x\r\n\r\n"), "x\r\n\r\n", "sealed idempotent");
        eq(InjectServer.sealed("x"), "x\r\n\r\n", "sealed append");

        eq(InjectServer.statusOf("HTTP/1.1 200 OK"), 200, "status 200");
        eq(InjectServer.statusOf("HTTP/1.1 407 Proxy Authentication Required"), 407, "status 407");
        eq(InjectServer.statusOf("HTTP/1.1 200"), 200, "status no reason");
        /* line() 交出来的串带 CRLF：网关只回 "HTTP/1.1 200\r\n"（没有原因短语）时，
         * 2.0.1 把行尾的 \r 当成非法字符整行判 0 —— 握手永远失败。 */
        eq(InjectServer.statusOf("HTTP/1.1 200\r\n"), 200, "status no reason + CRLF");
        eq(InjectServer.statusOf("HTTP/1.1 200 OK\r\n"), 200, "status + CRLF");
        eq(InjectServer.statusOf("garbage"), 0, "status garbage");
        eq(InjectServer.statusOf(""), 0, "status empty");
        eq(InjectServer.statusOf("HTTP/1.1 20a"), 0, "status non-digit");

        ok(InjectServer.isIp("1.2.3.4"), "isIp v4");
        ok(!InjectServer.isIp("1.2.3"), "isIp short v4");
        ok(InjectServer.isIp("::1"), "isIp v6");
        ok(!InjectServer.isIp("example.com"), "isIp domain");

        eq(InjectServer.withFraming("HTTP/1.1 200 OK\r\n\r\n", 0), "HTTP/1.1 200 OK\r\n\r\n", "framing none");
        eq(InjectServer.withFraming("HTTP/1.1 200 OK\r\n\r\n", 5),
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "framing length");
        eq(InjectServer.withFraming("HTTP/1.1 200 OK\r\n\r\n", -1),
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "framing chunked");
        eq(InjectServer.brief("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), "GET / HTTP/1.1 | Host: a |  |", "brief");
    }

    /* ----------------------------------------------------------- inject paths */

    private static void injectPaths() throws Exception {
        section("InjectServer paths");

        /* 分派表必须整表填满：2.0.1 只填了「遍历 http 槽 flags 能走到」的格子，
         * PATH[0][1][1]（80 端口交给 https 槽、https 槽有网关）留在默认 0 —— 直连。 */
        eq(path(0, 0, 0), 0, "PATH 80/http/no-gw = direct");
        eq(path(0, 0, 1), 2, "PATH 80/http/gw = http slot");
        eq(path(0, 1, 0), 0, "PATH 80/https/no-gw = direct");
        eq(path(0, 1, 1), 1, "PATH 80/https/gw = connect");
        eq(path(1, 1, 0), 0, "PATH other/https/no-gw = direct");
        eq(path(1, 1, 1), 1, "PATH other/https/gw = connect");

        /* http_ip 空 + https_ip 有值：80 端口由 https 槽接管，网关必须收到 CONNECT。
         * 2.0.1 这一格是 0，网关收到的是明文 GET（还会被倒在 443 端口上）——
         * 直播间、网页打不开的直接原因。 */
        TunnelGw tunnel = new TunnelGw("HTTP/1.1 200 OK\r\n\r\n");
        Ini tc = new Ini();
        tc.httpOn = true;
        tc.httpDirect = false;
        tc.httpIp = "";
        tc.httpFirst = "[M] [U] [V]\r\nHost: [H]\r\nX-Inject: 1";
        tc.httpsIp = "127.0.0.1";
        tc.httpsPort = tunnel.port();
        tc.httpsFirst = "CONNECT [H] HTTP/1.1\r\nHost: [H]\r\n";
        InjectServer tsrv = new InjectServer(tc, new HttpDns());
        int tport = tsrv.start(0);
        try {
            Socket s = new Socket("127.0.0.1", tport);
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            out.write("CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            ok(readHead(s.getInputStream()).startsWith("HTTP/1.1 200"), "https takeover 200");
            eq(tunnel.awaitHead(), "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
                    "https takeover gateway saw CONNECT");
            out.write("GET /live HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            eq(tunnel.await(40), "GET /live HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "https takeover tunnels raw bytes");
            s.close();
        } finally {
            tsrv.stop();
            tunnel.close();
        }

        /* 443 槽：模板 CONNECT → 网关 200 → 双向转发 */
        Gateway gw = new Gateway(Reply.OK, true);
        Ini c = new Ini();
        c.httpsIp = "127.0.0.1";
        c.httpsPort = gw.port();
        c.httpsFirst = "CONNECT [H] HTTP/1.1\r\nHost: [H]\r\nX-Tpl: 1";
        InjectServer srv = new InjectServer(c, new HttpDns());
        int port = srv.start(0);
        try {
            Socket s = new Socket("127.0.0.1", port);
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            out.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String resp = readHead(s.getInputStream());
            ok(resp.startsWith("HTTP/1.1 200"), "connect path 200: " + resp);
            String seen = gw.awaitHead();
            ok(seen.startsWith("CONNECT example.com:443 HTTP/1.1"), "gateway saw injected first line: " + seen);
            ok(seen.contains("Host: example.com:443"), "gateway saw host:port");
            ok(seen.contains("X-Tpl: 1"), "gateway saw template header");
            s.close();
        } finally {
            srv.stop();
            gw.close();
        }

        /* 80 槽：先答隧道，再改写首条请求；http_del 与模板头名都去重 */
        gw = new Gateway(Reply.OK, false);
        c = new Ini();
        c.httpIp = "127.0.0.1";
        c.httpPort = gw.port();
        c.httpFirst = "[M] [U] [V]\r\nHost: [H]\r\nX-Inject: 1";
        c.httpDel = "Host,X-Online-Host";
        srv = new InjectServer(c, new HttpDns());
        port = srv.start(0);
        try {
            Socket s = new Socket("127.0.0.1", port);
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            out.write("CONNECT origin.example:80 HTTP/1.1\r\nHost: origin.example:80\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            ok(readHead(s.getInputStream()).startsWith("HTTP/1.1 200"), "http slot tunnel 200");
            out.write(("GET /a?b=1 HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: UA\r\n"
                    + "X-Online-Host: origin.example\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String seen = gw.awaitHead();
            ok(seen.startsWith("GET /a?b=1 HTTP/1.1"), "http slot first line rewritten: " + seen);
            ok(seen.contains("X-Inject: 1"), "http slot template header");
            ok(seen.contains("User-Agent: UA"), "http slot keeps client header");
            ok(!seen.contains("X-Online-Host"), "http slot drops listed header");
            ok(count(seen, "Host:") == 1, "http slot one Host only: " + seen);
            s.close();
        } finally {
            srv.stop();
            gw.close();
        }

        /* 无网关：直连目标，一个字节都不改 */
        Target target = new Target();
        c = new Ini();
        c.httpsIp = "";
        c.httpIp = "";
        HttpDns direct = new HttpDns();
        direct.policy = Profile.DNS_DIRECT;
        srv = new InjectServer(c, direct);
        port = srv.start(0);
        try {
            Socket s = new Socket("127.0.0.1", port);
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            out.write(("CONNECT 127.0.0.1:" + target.port() + " HTTP/1.1\r\nHost: 127.0.0.1:"
                    + target.port() + "\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            ok(readHead(s.getInputStream()).startsWith("HTTP/1.1 200"), "direct tunnel 200");
            out.write("RAW".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            eq(target.await(3), "RAW", "direct path untouched");
            s.close();
        } finally {
            srv.stop();
            target.close();
        }

        /* 头后紧跟数据（TLS ClientHello 就是这样）：一次性写出去，块读多读的字节
         * 必须原样进入隧道，不能被当成头的一部分丢掉。 */
        Target early = new Target();
        c = new Ini();
        c.httpsIp = "";
        c.httpIp = "";
        srv = new InjectServer(c, direct);
        port = srv.start(0);
        try {
            Socket s = new Socket("127.0.0.1", port);
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            out.write(("CONNECT 127.0.0.1:" + early.port() + " HTTP/1.1\r\nHost: 127.0.0.1:"
                    + early.port() + "\r\n\r\nEARLY-HELLO").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            ok(readHead(s.getInputStream()).startsWith("HTTP/1.1 200"), "early 200");
            eq(early.await(11), "EARLY-HELLO", "early data forwarded");
            s.close();
        } finally {
            srv.stop();
            early.close();
        }

        /* 1200 字节的 Cookie 头：跨多个读块，头边界与尾随数据都要正确 */
        Target longHead = new Target();
        c = new Ini();
        c.httpsIp = "";
        c.httpIp = "";
        srv = new InjectServer(c, direct);
        port = srv.start(0);
        try {
            Socket s = new Socket("127.0.0.1", port);
            s.setSoTimeout(5000);
            StringBuilder req = new StringBuilder();
            req.append("CONNECT 127.0.0.1:").append(longHead.port())
                    .append(" HTTP/1.1\r\nHost: 127.0.0.1:").append(longHead.port())
                    .append("\r\nCookie: ");
            for (int i = 0; i < 1200; i++) req.append((char) ('a' + i % 26));
            req.append("\r\n\r\nTAIL");
            s.getOutputStream().write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            ok(readHead(s.getInputStream()).startsWith("HTTP/1.1 200"), "long head 200");
            eq(longHead.await(4), "TAIL", "long head tail forwarded");
            s.close();
        } finally {
            srv.stop();
            longHead.close();
        }

        /* 模板被拒 → 回退普通 CONNECT */
        gw = new Gateway(Reply.REJECT_TPL, false);
        c = new Ini();
        c.httpsIp = "127.0.0.1";
        c.httpsPort = gw.port();
        c.httpsFirst = "CONNECT [H] HTTP/1.1\r\nHost: [H]\r\nX-Tpl: 1";
        c.injectFallback = true;
        srv = new InjectServer(c, new HttpDns());
        port = srv.start(0);
        try {
            Socket s = new Socket("127.0.0.1", port);
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            out.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            ok(readHead(s.getInputStream()).startsWith("HTTP/1.1 200"), "fallback eventually 200");
            List<String> heads = gw.awaitHeads(2);
            eq(heads.size(), 2, "fallback tried twice");
            ok(heads.get(0).contains("X-Tpl: 1"), "first attempt template");
            ok(heads.get(1).startsWith("CONNECT example.com:443 HTTP/1.1"), "second attempt plain");
            s.close();
        } finally {
            srv.stop();
            gw.close();
        }

        /* DNS 策略 block：本地解析拒绝，连接直接关掉 */
        c = new Ini();
        c.httpsIp = "gw.example.com";
        HttpDns blocked = new HttpDns();
        blocked.policy = Profile.DNS_BLOCK;
        srv = new InjectServer(c, blocked);
        port = srv.start(0);
        try {
            Socket s = new Socket("127.0.0.1", port);
            s.setSoTimeout(5000);
            s.getOutputStream().write("CONNECT blocked.example:443 HTTP/1.1\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            eq(s.getInputStream().read(), -1, "blocked DNS closes connection");
            s.close();
        } finally {
            srv.stop();
        }
    }

    private static int count(String s, String needle) {
        int n = 0;
        int i = 0;
        while ((i = s.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }

    /** 注入器内部的分派表：只给测试用，跑运行时用的就是这张表。 */
    private static int path(int slot, int use, int gw) throws Exception {
        java.lang.reflect.Field f = InjectServer.class.getDeclaredField("PATH");
        f.setAccessible(true);
        int[][][] p = (int[][][]) f.get(null);
        return p[slot][use][gw];
    }

    private static String readHead(InputStream in) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int st = 0;
        while (b.size() < 8192) {
            int c = in.read();
            if (c < 0) break;
            b.write(c);
            if (c == '\r' && (st == 0 || st == 2)) st++;
            else if (c == '\n' && (st == 1 || st == 3)) st++;
            else st = 0;
            if (st == 4) break;
        }
        return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    private enum Reply {OK, REJECT_TPL}

    /** 假网关：读头、按策略回 200/400；可选在隧道建立后回一段内容。 */
    private static final class Gateway {
        private final ServerSocket ss;
        private final List<String> heads = new ArrayList<String>();
        private final List<Socket> sockets = new ArrayList<Socket>();
        private final Thread thread;

        Gateway(final Reply mode, final boolean push) throws Exception {
            ss = new ServerSocket(0);
            thread = new Thread(new Runnable() {
                public void run() {
                    try {
                        while (true) {
                            final Socket s = ss.accept();
                            sockets.add(s);
                            s.setSoTimeout(5000);
                            String head = readHead(s.getInputStream());
                            synchronized (heads) {
                                heads.add(head);
                            }
                            boolean tpl = head.contains("X-Tpl");
                            int code = mode == Reply.REJECT_TPL && tpl ? 400 : 200;
                            s.getOutputStream().write(("HTTP/1.1 " + code + " X\r\n\r\n")
                                    .getBytes(StandardCharsets.ISO_8859_1));
                            s.getOutputStream().flush();
                            if (push && code == 200) {
                                s.getOutputStream().write("HELLO".getBytes(StandardCharsets.ISO_8859_1));
                                s.getOutputStream().flush();
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            });
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return ss.getLocalPort();
        }

        String awaitHead() throws Exception {
            return awaitHeads(1).get(0);
        }

        List<String> awaitHeads(int n) throws Exception {
            for (int i = 0; i < 100; i++) {
                synchronized (heads) {
                    if (heads.size() >= n) return new ArrayList<String>(heads);
                }
                Thread.sleep(20);
            }
            synchronized (heads) {
                return new ArrayList<String>(heads);
            }
        }

        void close() {
            try {
                ss.close();
            } catch (Exception ignored) {
            }
            for (Socket s : sockets) {
                try {
                    s.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /** 假免流网关：读一个头、回固定状态行，之后把隧道里的字节原样回送。 */
    private static final class TunnelGw {
        private final ServerSocket ss;
        private final String reply;
        private final AtomicReference<String> head = new AtomicReference<String>("");
        private final AtomicReference<String> body = new AtomicReference<String>("");
        private final List<Socket> sockets = new ArrayList<Socket>();

        TunnelGw(final String reply) throws Exception {
            this.reply = reply;
            ss = new ServerSocket(0);
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        Socket s = ss.accept();
                        sockets.add(s);
                        head.set(readHead(s.getInputStream()));
                        s.getOutputStream().write(reply.getBytes(StandardCharsets.ISO_8859_1));
                        s.getOutputStream().flush();
                        byte[] b = new byte[256];
                        int n = s.getInputStream().read(b);
                        if (n > 0) body.set(new String(b, 0, n, StandardCharsets.ISO_8859_1));
                    } catch (Exception ignored) {
                    }
                }
            });
            t.setDaemon(true);
            t.start();
        }

        int port() {
            return ss.getLocalPort();
        }

        String awaitHead() throws Exception {
            for (int i = 0; i < 100 && head.get().length() == 0; i++) Thread.sleep(20);
            return head.get();
        }

        String await(int ms) throws Exception {
            long end = System.currentTimeMillis() + ms * 100L;
            while (System.currentTimeMillis() < end) {
                if (body.get().length() > 0) return body.get();
                Thread.sleep(20);
            }
            return body.get();
        }

        void close() {
            try {
                ss.close();
            } catch (Exception ignored) {
            }
            for (Socket s : sockets) {
                try {
                    s.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /** 假目标：连上后把收到的字节原样回送。 */
    private static final class Target {
        private final ServerSocket ss;
        private final AtomicReference<String> got = new AtomicReference<String>("");

        Target() throws Exception {
            ss = new ServerSocket(0);
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        Socket s = ss.accept();
                        InputStream in = s.getInputStream();
                        OutputStream out = s.getOutputStream();
                        byte[] b = new byte[64];
                        int n = in.read(b);
                        if (n > 0) {
                            got.set(new String(b, 0, n, StandardCharsets.ISO_8859_1));
                            out.write(b, 0, n);
                            out.flush();
                        }
                        s.close();
                    } catch (Exception ignored) {
                    }
                }
            });
            t.setDaemon(true);
            t.start();
        }

        int port() {
            return ss.getLocalPort();
        }

        String await(int ms) throws Exception {
            long end = System.currentTimeMillis() + ms * 100L;
            while (System.currentTimeMillis() < end) {
                String s = got.get();
                if (s.length() > 0) return s;
                Thread.sleep(20);
            }
            return got.get();
        }

        void close() {
            try {
                ss.close();
            } catch (Exception ignored) {
            }
        }
    }

    /* -------------------------------------------------------------------- dns */

    private static void dnsCodec() throws Exception {
        section("DNS codec");
        byte[] q = Dns.query("a.bc", Dns.A);
        eq(q[0], (byte) 0x12, "query id");
        eq(q[5], (byte) 1, "qdcount");
        eq(q[12], (byte) 1, "label len");
        eq(q[13], (byte) 'a', "label a");
        eq(q[14], (byte) 2, "label len 2");
        eq(q[15], (byte) 'b', "label b");
        eq(q[q.length - 4], (byte) 0, "qtype hi");
        eq(q[q.length - 3], (byte) 1, "qtype A");
        eq(q[q.length - 1], (byte) 1, "qclass");

        HttpDns dns = new HttpDns() {
            public String resolve(String host) {
                return "1.2.3.4";
            }
        };
        byte[] req = Dns.query("x.y", Dns.A);
        byte[] resp = Dns.answer(req, dns);
        eq((resp[6] & 0xFF) << 8 | (resp[7] & 0xFF), 1, "answer count A");
        eq(Dns.firstA(resp), "1.2.3.4", "firstA");
        eq(Dns.firstAAAA(resp), null, "no AAAA in A answer");

        HttpDns v6 = new HttpDns() {
            public String resolve(String host) {
                return "2001:db8::1";
            }
        };
        byte[] req6 = Dns.query("x.y", Dns.AAAA);
        byte[] resp6 = Dns.answer(req6, v6);
        ok(Dns.firstAAAA(resp6) != null && Dns.firstAAAA(resp6).contains("2001:db8"), "firstAAAA");
        eq(Dns.firstA(resp6), null, "no A in AAAA answer");

        /* CNAME 在前、A 在后：必须跳过第一条继续找 */
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(new byte[]{0, 1, (byte) 0x81, (byte) 0x80, 0, 1, 0, 2, 0, 0, 0, 0});
        b.write(new byte[]{1, 'x', 1, 'y', 0, 0, 1, 0, 1});
        b.write(new byte[]{(byte) 0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0, 0});
        b.write(new byte[]{(byte) 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 9, 8, 7, 6});
        eq(Dns.firstA(b.toByteArray()), "9.8.7.6", "firstA skips CNAME");

        eq(Dns.answer(new byte[]{1, 2, 3}, dns), null, "short request");
        byte[] bad = Dns.query("x.y", Dns.A);
        bad[5] = 2;
        eq(Dns.answer(bad, dns), null, "multi-question refused");
    }

    private static void ipLiterals() {
        section("IP literals");
        ok(HttpDns.isV4("0.0.0.0"), "isV4 zero");
        ok(HttpDns.isV4("255.255.255.255"), "isV4 max");
        ok(!HttpDns.isV4("256.1.1.1"), "isV4 >255");
        ok(!HttpDns.isV4("1.2.3"), "isV4 three parts");
        ok(!HttpDns.isV4("1.2.3.4."), "isV4 trailing dot");
        ok(!HttpDns.isV4("1.2.3.a"), "isV4 letter");
        ok(HttpDns.isIp("::1"), "isIp loopback");
        ok(HttpDns.isIp("fe80::1%1"), "isIp zone");
        ok(!HttpDns.isIp("fe80::1%wlan0"), "isIp zone name rejected (same as before)");
        ok(!HttpDns.isIp("[::1]"), "isIp brackets rejected");
        ok(!HttpDns.isIp("example.com"), "isIp domain");
        eq(HttpDns.firstV4("ip=1.2.3.4;"), "1.2.3.4", "firstV4");
        eq(HttpDns.firstV4("v999.1.1.1"), null, "firstV4 invalid");
        eq(HttpDns.firstV4("1.2.3.4a"), null, "firstV4 boundary");
    }

    /* ------------------------------------------------------------------ model */

    private static void nodes() {
        section("Node");
        ok(Node.isPrivateHost("10.1.2.3"), "private 10/8");
        ok(Node.isPrivateHost("172.16.0.1"), "private 172.16");
        ok(Node.isPrivateHost("172.31.255.255"), "private 172.31");
        ok(!Node.isPrivateHost("172.32.0.1"), "public 172.32");
        ok(Node.isPrivateHost("192.168.1.1"), "private 192.168");
        ok(!Node.isPrivateHost("8.8.8.8"), "public 8.8.8.8");
        ok(Node.isPrivateHost("localhost"), "localhost");
        ok(Node.isPrivateHost("nas.local"), "suffix local");
        ok(!Node.isPrivateHost("example.com"), "public domain");
        ok(Node.isPrivateHost("fd00::1"), "private v6");
        ok(!Node.isPrivateHost("2001:db8::1"), "public v6");

        Node n = new Node(Node.VLESS, "1.1.1.1", 443);
        eq(n.kind(), Kinds.VLESS, "kind vless");
        n.type = Node.TROJAN;
        eq(n.kind(), Kinds.TROJAN, "kind cache invalidates");
        n.net = "ws";
        eq(n.netId(), Kinds.NET_WS, "net id");
        n.security = "reality";
        eq(n.secId(), Kinds.SEC_REALITY, "sec id");

        Node u = new Node(Node.TROJAN, "2.2.2.2", 443);
        u.uot = false;
        ok(!Node.udpOverTcp(u), "trojan without uot");
        u.uot = true;
        ok(Node.udpOverTcp(u), "trojan with uot");
        ok(Node.udpOverTcp(new Node(Node.VLESS, "h", 1)), "vless udp over tcp");
        ok(!Node.udpOverTcp(new Node(Node.SOCKS, "h", 1)), "socks udp not over tcp");
        ok(!Node.udpCapable(Node.HTTP), "http not udp capable");

        String fp1 = n.fingerprint();
        n.host = "9.9.9.9";
        ok(!fp1.equals(n.fingerprint()), "fingerprint tracks host");

        Node host = new Node(Node.INJECT, "", 0);
        host.udpNode = u.copy();
        host.udpSrcProfile = "p1";
        host.udpSrcIndex = 2;
        host.udpSrcFp = "abc";
        Node back = Node.fromJson(host.toJson());
        ok(back.udpNode != null, "udp node json");
        eq(back.udpSrcProfile, "p1", "udp source id json");
        eq(back.udpSrcIndex, 2, "udp source index json");
        eq(back.udpSrcFp, "abc", "udp source fp json");
    }

    private static void profiles() {
        section("Profile");
        Profile p = new Profile();
        p.udpPolicy = "bogus";
        eq(p.effectiveUdpPolicy(), Profile.UDP_BLOCK, "invalid udp policy falls back");
        p.dnsPolicy = "";
        eq(p.effectiveDnsPolicy(), Profile.DNS_PROXY, "empty dns policy falls back");

        Node inj = new Node(Node.INJECT, "", 0);
        Profile one = new Profile("one");
        one.chain.add(inj);
        eq(one.udpSplit(), null, "no udp node");
        Node u = new Node(Node.VLESS, "1.1.1.1", 443);
        inj.udpNode = u;
        ok(one.udpSplit() != null, "udp split single inject");
        u.host = "";
        eq(one.udpSplit(), null, "udp split empty host");
        u.host = "1.1.1.1";
        u.type = Node.HTTP;
        eq(one.udpSplit(), null, "http not udp capable");
        u.type = Node.VLESS;
        one.chain.add(new Node(Node.SS, "2.2.2.2", 8388));
        eq(one.udpSplit(), null, "chain of two hides udp");

        Profile copy = one.copy();
        eq(copy.chain.size(), 2, "copy chain");
        eq(copy.chain.get(0).udpNode.host, "1.1.1.1", "copy nested udp");
        Profile json = Profile.fromJson(one.toJson());
        eq(json.chain.size(), 2, "profile json chain");
        eq(json.chain.get(0).udpNode.type, Node.VLESS, "profile json udp node");
    }

    /* ------------------------------------------------------------------- conf */

    private static Store.Settings settings() {
        return new Store.Settings();
    }

    private static Profile single(String type) {
        Profile p = new Profile(type);
        Node n = new Node(type, "1.2.3.4", 443);
        n.uuid = "00000000-0000-0000-0000-000000000000";
        n.password = "pw";
        n.user = "u";
        p.chain.add(n);
        return p;
    }

    private static void confProtocols() throws Exception {
        section("Conf protocols");
        String[][] expect = {
                {Node.VLESS, "vless"}, {Node.VMESS, "vmess"}, {Node.TROJAN, "trojan"},
                {Node.SS, "shadowsocks"}, {Node.SOCKS, "socks"}, {Node.HTTP, "http"},
        };
        for (String[] e : expect) {
            Profile p = single(e[0]);
            JSONObject c = Conf.build(p, settings(), false, 0);
            JSONObject o = c.getJSONArray("outbounds").getJSONObject(0);
            eq(o.getString("protocol"), e[1], "protocol " + e[0]);
        }
        Profile p = single(Node.VMESS);
        p.chain.get(0).security = "tls";
        JSONObject vn = Conf.build(p, settings(), false, 0)
                .getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0);
        eq(vn.getJSONArray("users").getJSONObject(0).getInt("alterId"), 0, "vmess alterId");
        eq(vn.getJSONArray("users").getJSONObject(0).getString("security"), "auto", "vmess scy default");
    }

    private static void confStreams() throws Exception {
        section("Conf streams");
        String[][] nets = {
                {"tcp", "tcp", ""}, {"ws", "ws", "wsSettings"}, {"grpc", "grpc", "grpcSettings"},
                {"httpupgrade", "httpupgrade", "httpupgradeSettings"}, {"xhttp", "xhttp", "xhttpSettings"},
                {"kcp", "kcp", "kcpSettings"}, {"h2", "xhttp", "xhttpSettings"},
                {"http", "xhttp", "xhttpSettings"}, {"quic", "xhttp", "xhttpSettings"},
        };
        for (String[] row : nets) {
            Profile p = single(Node.VLESS);
            Node n = p.chain.get(0);
            n.net = row[0];
            n.path = "/p";
            if ("quic".equals(row[0])) n.security = "tls";
            JSONObject ss = Conf.build(p, settings(), false, 0)
                    .getJSONArray("outbounds").getJSONObject(0)
                    .getJSONObject("streamSettings");
            eq(ss.getString("network"), row[1], "net " + row[0]);
            if (row[2].length() > 0) ok(ss.has(row[2]), "settings " + row[0]);
            if ("h2".equals(row[0]) || "http".equals(row[0])) {
                eq(ss.getJSONObject("xhttpSettings").getString("mode"), "stream-one", "migrated mode " + row[0]);
            }
            if ("quic".equals(row[0])) {
                eq(ss.getJSONObject("xhttpSettings").getString("mode"), "stream-one", "quic to stream-one");
                eq(ss.getJSONObject("tlsSettings").getJSONArray("alpn").getString(0), "h3", "quic h3 alpn");
            }
        }

        for (String sec : new String[]{"none", "tls", "reality"}) {
            Profile p = single(Node.VLESS);
            Node n = p.chain.get(0);
            n.security = sec;
            n.sni = "s.example";
            n.fp = "chrome";
            n.pbk = "pbk";
            n.sid = "sid";
            JSONObject ss = Conf.build(p, settings(), false, 0)
                    .getJSONArray("outbounds").getJSONObject(0)
                    .getJSONObject("streamSettings");
            eq(ss.getString("security"), sec, "security " + sec);
            if ("tls".equals(sec)) eq(ss.getJSONObject("tlsSettings").getString("serverName"), "s.example", "tls sni");
            if ("reality".equals(sec)) eq(ss.getJSONObject("realitySettings").getString("publicKey"), "pbk", "reality pbk");
        }
    }

    /** 2.0.3 补齐的字段：每项都要真的落到 xray 配置里，不然界面填了等于没填。 */
    private static void confAdvanced() throws Exception {
        section("Conf advanced");

        /* VLESS encryption + KCP 的 seed/mtu/tti/头伪装（finalmask） */
        Profile p = single(Node.VLESS);
        Node n = p.chain.get(0);
        n.encryption = "mlkem768x25519plus.native.600s.AAAA";
        n.net = "kcp";
        n.kcpSeed = "s3cr3t";
        n.kcpMtu = 1200;
        n.kcpTti = 30;
        n.headerType = "wechat-video";
        JSONObject out = Conf.build(p, settings(), false, 0)
                .getJSONArray("outbounds").getJSONObject(0);
        eq(out.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                        .getJSONArray("users").getJSONObject(0).getString("encryption"),
                "mlkem768x25519plus.native.600s.AAAA", "vless encryption");
        JSONObject ss = out.getJSONObject("streamSettings");
        eq(ss.getJSONObject("kcpSettings").getInt("mtu"), 1200, "kcp mtu");
        eq(ss.getJSONObject("kcpSettings").getInt("tti"), 30, "kcp tti");
        ok(!ss.getJSONObject("kcpSettings").has("header"), "kcp header 不再写进 kcpSettings");
        ok(!ss.getJSONObject("kcpSettings").has("seed"), "kcp seed 不再写进 kcpSettings");
        JSONObject mask = ss.getJSONObject("finalmask").getJSONArray("udp").getJSONObject(0);
        eq(mask.getString("type"), "mkcp-legacy", "kcp mask type");
        eq(mask.getJSONObject("settings").getString("header"), "wechat", "kcp mask header");
        eq(mask.getJSONObject("settings").getString("value"), "s3cr3t", "kcp mask seed");

        /* 不给头伪装、不给 seed 时也要写一条空的 mkcp-legacy：官方说这样才是旧版默认 XOR，
         * 少了它连不上老服务端。 */
        p = single(Node.VLESS);
        n = p.chain.get(0);
        n.net = "kcp";
        n.headerType = "none";
        n.kcpSeed = "";
        ss = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings");
        eq(ss.getJSONObject("finalmask").getJSONArray("udp").getJSONObject(0).getString("type"),
                "mkcp-legacy", "kcp plain still has mask");
        ok(!ss.getJSONObject("finalmask").getJSONArray("udp").getJSONObject(0).has("settings"),
                "kcp plain mask has no settings");

        /* 越界的 mtu/tti 会让内核拒载整份配置，这里要落回默认值 */
        n.kcpMtu = 9000;
        n.kcpTti = 1;
        ss = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings");
        eq(ss.getJSONObject("kcpSettings").getInt("mtu"), 1350, "kcp mtu clamped");
        eq(ss.getJSONObject("kcpSettings").getInt("tti"), 50, "kcp tti clamped");

        /* gRPC multi / XHTTP mode + extra */
        p = single(Node.VLESS);
        n = p.chain.get(0);
        n.net = "grpc";
        n.serviceName = "gs";
        n.hostHdr = "auth.example";
        n.grpcMode = "multi";
        ss = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings");
        eq(ss.getJSONObject("grpcSettings").getBoolean("multiMode"), true, "grpc multiMode");
        eq(ss.getJSONObject("grpcSettings").getString("authority"), "auth.example", "grpc authority");

        p = single(Node.VLESS);
        n = p.chain.get(0);
        n.net = "xhttp";
        n.path = "/xh";
        n.xhttpMode = "packet-up";
        n.xhttpExtra = "{\"xmux\":{\"maxConcurrency\":\"16-32\"}}";
        ss = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings");
        eq(ss.getJSONObject("xhttpSettings").getString("mode"), "packet-up", "xhttp mode");
        ok(ss.getJSONObject("xhttpSettings").has("extra"), "xhttp extra");

        /* 非法的 extra / finalmask 不能把配置搞挂 */
        n.xhttpExtra = "not json";
        n.finalMask = "{broken";
        ss = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings");
        ok(!ss.getJSONObject("xhttpSettings").has("extra"), "bad extra ignored");
        ok(!ss.has("finalmask"), "bad finalmask ignored");
        n.xhttpMode = "bogus";
        ss = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings");
        eq(ss.getJSONObject("xhttpSettings").getString("mode"), "auto", "bad xhttp mode falls back");

        /* TCP + headerType=http 的伪装请求 */
        p = single(Node.VLESS);
        n = p.chain.get(0);
        n.net = "tcp";
        n.headerType = "http";
        n.path = "/a,/b";
        n.hostHdr = "h1.com";
        ss = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings");
        JSONObject hdr = ss.getJSONObject("tcpSettings").getJSONObject("header");
        eq(hdr.getString("type"), "http", "tcp header type");
        eq(hdr.getJSONObject("request").getJSONArray("path").length(), 2, "tcp request paths");
        eq(hdr.getJSONObject("request").getJSONArray("path").getString(1), "/b", "tcp second path");
        eq(hdr.getJSONObject("request").getJSONObject("headers").getJSONArray("Host").getString(0),
                "h1.com", "tcp request host");

        /* TLS 三项 + reality mldsa + pin 压掉 allowInsecure */
        p = single(Node.VLESS);
        n = p.chain.get(0);
        n.security = "tls";
        n.sni = "s.example";
        n.allowInsecure = true;
        n.pinnedCA = "AAAA";
        n.ech = "ech-config";
        n.verifyPeer = "s.example";
        JSONObject tls = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("tlsSettings");
        eq(tls.getBoolean("allowInsecure"), false, "pin beats allowInsecure");
        eq(tls.getString("echConfigList"), "ech-config", "tls ech");
        eq(tls.getString("verifyPeerCertByName"), "s.example", "tls verifyPeer");
        eq(tls.getString("pinnedPeerCertSha256"), "AAAA", "tls pinned cert");

        p = single(Node.VLESS);
        n = p.chain.get(0);
        n.security = "reality";
        n.pbk = "PK";
        n.mldsa = "MLDSA";
        JSONObject r = Conf.build(p, settings(), false, 0).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("realitySettings");
        eq(r.getString("mldsa65Verify"), "MLDSA", "reality mldsa");
    }

    private static void confChains() throws Exception {
        section("Conf chains");
        Profile p = new Profile("chain");
        p.chain.add(new Node(Node.VLESS, "1.1.1.1", 443));
        p.chain.add(new Node(Node.TROJAN, "2.2.2.2", 443));
        JSONArray outs = Conf.build(p, settings(), false, 0).getJSONArray("outbounds");
        eq(outs.length(), 5, "chain outbound count (2 hops + direct + block + dns-out)");
        eq(outs.getJSONObject(0).getString("tag"), "proxy", "exit first");
        eq(outs.getJSONObject(0).getString("protocol"), "trojan", "exit protocol");
        eq(outs.getJSONObject(0).getJSONObject("streamSettings").getJSONObject("sockopt")
                .getString("dialerProxy"), "hop0", "exit dialer");

        Profile inj = new Profile("inject");
        Node hop = new Node(Node.INJECT, "", 0);
        hop.ini = "https_ip=127.0.0.1;";
        inj.chain.add(hop);
        inj.chain.add(new Node(Node.VLESS, "1.1.1.1", 443));
        outs = Conf.build(inj, settings(), false, 45678).getJSONArray("outbounds");
        eq(outs.getJSONObject(0).getString("tag"), "proxy", "inject exit tag");
        eq(outs.getJSONObject(0).getJSONObject("streamSettings").getJSONObject("sockopt")
                .getString("dialerProxy"), "hopg", "inject exit dialer");
        eq(outs.getJSONObject(1).getString("protocol"), "http", "inject hop http outbound");
        eq(outs.getJSONObject(1).getJSONObject("settings").getJSONArray("servers")
                .getJSONObject(0).getInt("port"), 45678, "inject port");

        /* UDP 转换：经注入 → udp-out.dialerProxy=proxy；直连 → 没有 dialerProxy */
        Profile udp = new Profile("udp");
        Node ui = new Node(Node.INJECT, "", 0);
        ui.ini = "https_ip=127.0.0.1;";
        ui.udpNode = new Node(Node.VLESS, "3.3.3.3", 443);
        ui.udpViaInject = true;
        udp.chain.add(ui);
        udp.udpPolicy = Profile.UDP_PROXY;
        udp.quicPolicy = Profile.UDP_PROXY;
        outs = Conf.build(udp, settings(), false, 45678).getJSONArray("outbounds");
        JSONObject udpOut = findByTag(outs, Conf.TAG_UDP);
        ok(udpOut != null, "udp outbound present");
        eq(udpOut.getJSONObject("streamSettings").getJSONObject("sockopt")
                .getString("dialerProxy"), "proxy", "udp via inject dialer");

        ui.udpViaInject = false;
        outs = Conf.build(udp, settings(), false, 45678).getJSONArray("outbounds");
        udpOut = findByTag(outs, Conf.TAG_UDP);
        ok(udpOut != null, "udp direct outbound present");
        ok(!udpOut.getJSONObject("streamSettings").has("sockopt")
                || !udpOut.getJSONObject("streamSettings").getJSONObject("sockopt").has("dialerProxy"),
                "udp direct no dialer");

        udp.udpPolicy = Profile.UDP_BLOCK;
        udp.quicPolicy = Profile.UDP_BLOCK;
        outs = Conf.build(udp, settings(), false, 45678).getJSONArray("outbounds");
        eq(findByTag(outs, Conf.TAG_UDP), null, "udp outbound omitted when unused");
    }

    private static JSONObject findByTag(JSONArray a, String tag) {
        for (int i = 0; i < a.length(); i++) {
            JSONObject o = a.optJSONObject(i);
            if (o != null && tag.equals(o.optString("tag"))) return o;
        }
        return null;
    }

    private static void confRouting() throws Exception {
        section("Conf routing");
        Profile p = single(Node.VLESS);
        p.preset = Profile.P_BYPASS_CN;
        p.v6 = Profile.V6_BLOCK;
        p.udpPolicy = Profile.UDP_PROXY;
        p.quicPolicy = Profile.UDP_PROXY;
        Rule r = new Rule(Rule.F_DOMAIN_SUFFIX, "a.com,b.com", Rule.A_DIRECT);
        p.rules.add(r);
        JSONObject route = Conf.build(p, settings(), false, 0).getJSONObject("routing");
        JSONArray rules = route.getJSONArray("rules");
        boolean v6 = false;
        boolean bypassDomain = false;
        boolean userRule = false;
        for (int i = 0; i < rules.length(); i++) {
            JSONObject o = rules.getJSONObject(i);
            if (o.optJSONArray("ip") != null && o.getJSONArray("ip").optString(0).equals("::/0")) v6 = true;
            if (o.optJSONArray("domain") != null
                    && "geosite:cn".equals(o.getJSONArray("domain").optString(0))) bypassDomain = true;
            if (o.optJSONArray("domain") != null
                    && o.getJSONArray("domain").optString(0).equals("domain:a.com")) userRule = true;
        }
        ok(v6, "v6 block rule");
        ok(bypassDomain, "bypass cn domain rule");
        ok(userRule, "custom rule prefix");
        eq(p.effectiveDnsPolicy(), Profile.DNS_PROXY, "dns default");

        /* 每个字段都要落到正确的 JSON 键与前缀上。之前只看 domain:a.com，
         * 而"未知字段兜底"也产出 domain:a.com，测不出映射错位。 */
        String[][] expect = {
                {Rule.F_DOMAIN, "a.com", "domain", "full:a.com"},
                {Rule.F_DOMAIN_SUFFIX, "a.com", "domain", "domain:a.com"},
                {Rule.F_DOMAIN_KEYWORD, "a.com", "domain", "keyword:a.com"},
                {Rule.F_DOMAIN_REGEX, "a.com", "domain", "regexp:a.com"},
                {Rule.F_GEOSITE, "cn", "domain", "geosite:cn"},
                {Rule.F_IP, "10.0.0.0/8", "ip", "10.0.0.0/8"},
                {Rule.F_GEOIP, "cn", "ip", "geoip:cn"},
                {Rule.F_PORT, "8080", "port", "8080"},
                {Rule.F_PROCESS, "com.example", "process", "com.example"},
                {Rule.F_INBOUND, "socks-in", "inboundTag", "socks-in"},
                {Rule.F_NETWORK, "udp", "network", "udp"},
                {"bogus-field", "x", "domain", "domain:x"},
        };
        for (String[] e : expect) {
            Profile rp = single(Node.VLESS);
            rp.rules.add(new Rule(e[0], e[1], Rule.A_DIRECT));
            JSONArray rs = Conf.build(rp, settings(), false, 0)
                    .getJSONObject("routing").getJSONArray("rules");
            /* 用户规则排在预设/内置规则之后 */
            JSONObject only = rs.getJSONObject(rs.length() - 1);
            ok(only.has(e[2]), "rule " + e[0] + " -> key " + e[2] + " got " + only);
            String got = only.optJSONArray(e[2]) != null
                    ? only.getJSONArray(e[2]).optString(0) : only.optString(e[2]);
            eq(got, e[3], "rule " + e[0] + " value");
        }

        /* raw json：ext: 映射 + 空规则删除 */
        Profile raw = new Profile("raw");
        raw.rawJson = "{\"outbounds\":[{\"protocol\":\"freedom\",\"tag\":\"direct\"}],"
                + "\"routing\":{\"rules\":[{\"type\":\"field\",\"ip\":[\"ext:geoip.dat:cn\"],"
                + "\"outboundTag\":\"direct\"},{\"type\":\"field\",\"outboundTag\":\"proxy\"}]}}";
        JSONObject rc = Conf.build(raw, settings(), false, 0);
        JSONArray rr = rc.getJSONObject("routing").getJSONArray("rules");
        eq(rr.length(), 1, "empty raw rule dropped");
        eq(rr.getJSONObject(0).getJSONArray("ip").getString(0), "geoip:cn", "ext ip mapped");

        /* root 模式多两个入站，且 tproxy 绑双栈 */
        JSONObject root = Conf.build(single(Node.VLESS), settings(), true, 0);
        JSONArray in = root.getJSONArray("inbounds");
        eq(in.length(), 4, "root inbounds");
        boolean tproxy = false;
        for (int i = 0; i < in.length(); i++) if ("tproxy-in".equals(in.getJSONObject(i).optString("tag"))) tproxy = true;
        ok(tproxy, "tproxy inbound");
    }

    /* ------------------------------------------------------------------ links */

    private static void links() {
        section("Links");
        Node n = Links.parseLink("vless://uuid-1@example.com:443?type=ws&path=%2Fray&host=a.com&security=tls&sni=s.com&fp=chrome#node1");
        ok(n != null, "parse vless");
        eq(n.type, Node.VLESS, "vless type");
        eq(n.uuid, "uuid-1", "vless uuid");
        eq(n.net, "ws", "vless net");
        eq(n.path, "/ray", "vless path");
        eq(n.security, "tls", "vless security");
        eq(n.name, "node1", "vless name");

        n = Links.parseLink("trojan://pw@example.com:8443?security=reality&pbk=k&sid=s&sni=x.com#t");
        ok(n != null, "parse trojan");
        eq(n.type, Node.TROJAN, "trojan type");
        eq(n.port, 8443, "trojan port");
        eq(n.security, "reality", "trojan reality");

        String cred = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("aes-256-gcm:pw".getBytes(StandardCharsets.UTF_8));
        n = Links.parseLink("ss://" + cred + "@1.2.3.4:8388#ss");
        ok(n != null, "parse ss");
        eq(n.type, Node.SS, "ss type");
        eq(n.method, "aes-256-gcm", "ss method");
        eq(n.password, "pw", "ss password");

        n = Links.parseLink("socks://dXNlcjpwYXNz@1.2.3.4:1080#s5");
        ok(n != null, "parse socks");
        eq(n.type, Node.SOCKS, "socks type");

        String vm = "{\"v\":\"2\",\"ps\":\"vm\",\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"u\","
                + "\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"a.com\",\"path\":\"/p\","
                + "\"tls\":\"tls\",\"sni\":\"s.com\"}";
        String link = "vmess://" + java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(vm.getBytes(StandardCharsets.UTF_8));
        n = Links.parseLink(link);
        ok(n != null, "parse vmess");
        eq(n.type, Node.VMESS, "vmess type");
        eq(n.uuid, "u", "vmess uuid");
        eq(n.name, "vm", "vmess name");

        List<Profile> list = Links.parse("vless://u@a.com:443?security=tls#a\ntrojan://p@b.com:443#b");
        eq(list.size(), 2, "parse list");

        Profile cfg = Links.fromJsonConfig("{\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":\"vless\","
                + "\"settings\":{\"vnext\":[{\"address\":\"1.2.3.4\",\"port\":443,\"users\":[{\"id\":\"u\"}]}]},"
                + "\"streamSettings\":{\"network\":\"ws\",\"security\":\"tls\",\"wsSettings\":{\"path\":\"/x\",\"host\":\"h\"}}}],"
                + "\"routing\":{\"rules\":[{\"type\":\"field\",\"domain\":[\"geosite:cn\"],\"outboundTag\":\"direct\"}]}}");
        ok(cfg != null, "parse full config");
        eq(cfg.chain.size(), 1, "config chain");
        eq(cfg.chain.get(0).path, "/x", "config ws path");

        /* xray 的协议名是 shadowsocks，不是内部的 ss；导入时不能整条丢掉 */
        Profile ssCfg = Links.fromJsonConfig("{\"outbounds\":[{\"protocol\":\"shadowsocks\","
                + "\"settings\":{\"servers\":[{\"address\":\"1.2.3.4\",\"port\":8388,"
                + "\"method\":\"aes-256-gcm\",\"password\":\"p\"}]}}]}");
        ok(ssCfg != null && ssCfg.chain.size() == 1, "parse shadowsocks config");
        eq(ssCfg.chain.get(0).type, Node.SS, "shadowsocks type");
        eq(ssCfg.chain.get(0).method, "aes-256-gcm", "shadowsocks method");
        eq(ssCfg.chain.get(0).port, 8388, "shadowsocks port");

        String out = Links.toLink(Links.parseLink("vless://u@a.com:443?type=tcp&security=tls#n"));
        ok(out.startsWith("vless://"), "export vless");
        String vmOut = Links.toLink(Links.parseLink(link));
        ok(vmOut.startsWith("vmess://"), "export vmess");
    }

    /* --------------------------------------------------------- links advanced */

    /** v2rayNG 导出的链接里那些「这边以前没有」的参数，导入不能再丢。 */
    private static void linksAdvanced() {
        section("Links advanced");
        String link = "vless://u@a.com:443?type=kcp&headerType=srtp&seed=sd&mtu=1200&tti=30"
                + "&security=reality&pbk=K&sid=S&spx=%2Fsp&fp=chrome"
                + "&ech=EC&vcn=a.com&pcs=PC&pqv=ML&flow=xtls-rprx-vision#adv";
        Node n = Links.parseLink(link);
        ok(n != null, "parse advanced vless");
        eq(n.kcpSeed, "sd", "link kcp seed");
        eq(n.kcpMtu, 1200, "link kcp mtu");
        eq(n.kcpTti, 30, "link kcp tti");
        eq(n.headerType, "srtp", "link kcp header");
        eq(n.ech, "EC", "link ech");
        eq(n.verifyPeer, "a.com", "link vcn");
        eq(n.pinnedCA, "PC", "link pcs");
        eq(n.mldsa, "ML", "link pqv");
        eq(n.spx, "/sp", "link spx");

        String back = Links.toLink(n);
        ok(back.contains("seed=sd"), "export seed");
        ok(back.contains("mtu=1200"), "export mtu");
        ok(back.contains("pqv=ML"), "export pqv");
        Node again = Links.parseLink(back);
        ok(again != null, "reparse exported link");
        eq(again.kcpSeed, "sd", "roundtrip seed");
        eq(again.mldsa, "ML", "roundtrip mldsa");

        /* gRPC：serviceName / authority / mode */
        n = Links.parseLink("vless://u@a.com:443?type=grpc&serviceName=gs&authority=au&mode=multi#g");
        eq(n.serviceName, "gs", "link grpc serviceName");
        eq(n.hostHdr, "au", "link grpc authority");
        eq(n.grpcMode, "multi", "link grpc mode");
        back = Links.toLink(n);
        ok(back.contains("serviceName=gs") && back.contains("authority=au"), "export grpc keys");

        /* xhttp：splithttp 别名归一 + mode/extra */
        n = Links.parseLink("vless://u@a.com:443?type=splithttp&path=%2Fx&mode=stream-up#x");
        eq(n.net, "xhttp", "splithttp alias");
        eq(n.xhttpMode, "stream-up", "link xhttp mode");

        /* 旧版导出把 KCP seed 写在 path 里，升级后要能认出来 */
        n = Links.parseLink("vless://u@a.com:443?type=kcp&path=oldseed#old");
        eq(n.kcpSeed, "oldseed", "legacy path as kcp seed");
        eq(n.path, "", "legacy path cleared");

        /* 完整 JSON 配置里的新字段要能读进来 */
        Profile cfg = Links.fromJsonConfig("{\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":\"vless\","
                + "\"settings\":{\"vnext\":[{\"address\":\"1.2.3.4\",\"port\":443,"
                + "\"users\":[{\"id\":\"u\",\"encryption\":\"none\"}]}]},"
                + "\"streamSettings\":{\"network\":\"xhttp\",\"security\":\"tls\","
                + "\"xhttpSettings\":{\"path\":\"/x\",\"mode\":\"packet-up\","
                + "\"extra\":{\"xmux\":{\"maxConcurrency\":16}}},"
                + "\"tlsSettings\":{\"serverName\":\"s.com\",\"echConfigList\":\"EC\","
                + "\"pinnedPeerCertSha256\":\"PC\",\"allowInsecure\":true}}}]}");
        ok(cfg != null && cfg.chain.size() == 1, "parse advanced config");
        Node c = cfg == null || cfg.chain.isEmpty() ? null : cfg.chain.get(0);
        eq(c == null ? "" : c.xhttpMode, "packet-up", "config xhttp mode");
        ok(c != null && c.xhttpExtra.contains("xmux"), "config xhttp extra");
        eq(c == null ? "" : c.ech, "EC", "config ech");
        eq(c == null ? "" : c.pinnedCA, "PC", "config pin");
        eq(c != null && c.allowInsecure, true, "config insecure");
    }

    /* --------------------------------------------------------------- node sync */

    private static void nodeSync() {
        section("NodeSync");
        Store.I.profiles.clear();
        Profile src = new Profile("src");
        src.id = "src-1";
        Node a = new Node(Node.VLESS, "1.1.1.1", 443);
        a.uuid = "u";
        src.chain.add(a);

        Profile host = new Profile("host");
        host.id = "host-1";
        Node inj = new Node(Node.INJECT, "", 0);
        inj.ini = "https_ip=1.1.1.1;";
        inj.udpNode = a.copy();
        inj.udpViaInject = true;
        NodeSync.bindSource(inj, "src-1", 0, a);
        host.chain.add(inj);

        Store.I.profiles.add(src);
        Store.I.profiles.add(host);

        eq(NodeSync.reconcile(), 0, "no change no sync");
        a.host = "2.2.2.2";
        eq(NodeSync.reconcile(), 1, "source change detected");
        eq(inj.udpNode.host, "2.2.2.2", "copy refreshed");

        a.net = "kcp";
        eq(NodeSync.reconcile(), 1, "transport change detected");
        ok(!inj.udpViaInject, "kcp demotes via-inject to direct");

        src.chain.clear();
        eq(NodeSync.reconcile(), 0, "deleted source keeps copy");
        ok(inj.udpNode != null, "copy retained");
    }
}
