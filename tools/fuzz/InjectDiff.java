package com.lcs.tproxy.inject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * 注入器运行时差分：同一组场景分别跑 1.8.2 与 2.0.0 的 InjectServer，
 * 记录「客户端收到的字节」与「上游收到的字节」，两边逐字节比较。
 *
 * 端口号在输出里被替换成占位符，保证可 diff。
 */
public final class InjectDiff {

    private static int n;

    public static void main(String[] args) throws Exception {
        tunnelEarly();
        tunnelLongHead();
        tunnelHalfClose();
        tunnelTwoWrites();
        httpGet();
        httpKeepAlive();
        httpPostBody();
        httpDelHeaders();
        System.out.println("cases=" + n);
    }

    /* ------------------------------------------------------------ 隧道场景 */

    /** CONNECT 之后立刻跟数据（TLS ClientHello 就是这样）：块读多读的字节必须回退。 */
    private static void tunnelEarly() throws Exception {
        EchoUp up = new EchoUp();
        InjectServer srv = tunnelServer();
        try {
            Socket s = client(srv.port);
            OutputStream out = s.getOutputStream();
            out.write(("CONNECT 127.0.0.1:" + up.port + " HTTP/1.1\r\nHost: 127.0.0.1:" + up.port
                    + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write("EARLY-DATA-0123456789".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String head = readHead(s.getInputStream());
            byte[] echo = readN(s.getInputStream(), 21);
            out("tunnel-early", head + "|" + hex(echo), hex(up.await(21)));
            s.close();
        } finally {
            srv.stop();
            up.close();
        }
    }

    /** 一个 1200 字节的 Cookie 头：跨多个 512 块，头尾都要正确。 */
    private static void tunnelLongHead() throws Exception {
        EchoUp up = new EchoUp();
        InjectServer srv = tunnelServer();
        try {
            Socket s = client(srv.port);
            OutputStream out = s.getOutputStream();
            StringBuilder b = new StringBuilder();
            b.append("CONNECT 127.0.0.1:").append(up.port).append(" HTTP/1.1\r\nHost: 127.0.0.1:").append(up.port).append("\r\nCookie: ");
            for (int i = 0; i < 1200; i++) b.append((char) ('a' + i % 26));
            b.append("\r\n\r\n");
            out.write(b.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.write("TAIL".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String head = readHead(s.getInputStream());
            byte[] echo;
            try {
                echo = readN(s.getInputStream(), 4);
            } catch (Exception e) {
                out("tunnel-long-head-ERR", head + "|" + e + "|up=" + hex(up.await(0)), "");
                s.close();
                return;
            }
            out("tunnel-long-head", head + "|" + hex(echo), hex(up.await(4)));
            s.close();
        } finally {
            srv.stop();
            up.close();
        }
    }

    /** 客户端半关闭：上行 EOF 后，上游剩下的下行必须继续送到客户端。 */
    private static void tunnelHalfClose() throws Exception {
        EchoUp up = new EchoUp();
        InjectServer srv = tunnelServer();
        try {
            Socket s = client(srv.port);
            OutputStream out = s.getOutputStream();
            out.write(("CONNECT 127.0.0.1:" + up.port + " HTTP/1.1\r\nHost: 127.0.0.1:" + up.port + "\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.write("PING".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String head = readHead(s.getInputStream());
            readN(s.getInputStream(), 4);
            s.shutdownOutput();
            up.send("PONG-AFTER-EOF".getBytes(StandardCharsets.ISO_8859_1));
            byte[] rest = readN(s.getInputStream(), 13);
            out("tunnel-half-close", head + "|" + hex(rest), hex(up.await(4)));
            s.close();
        } finally {
            srv.stop();
            up.close();
        }
    }

    /** 分两次写、中间隔 50ms：不能被当成两个请求。 */
    private static void tunnelTwoWrites() throws Exception {
        EchoUp up = new EchoUp();
        InjectServer srv = tunnelServer();
        try {
            Socket s = client(srv.port);
            OutputStream out = s.getOutputStream();
            out.write(("CONNECT 127.0.0.1:" + up.port + " HTTP/1.1\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            Thread.sleep(50);
            out.write(("Host: 127.0.0.1:" + up.port + "\r\n\r\nAB").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String head = readHead(s.getInputStream());
            byte[] echo = readN(s.getInputStream(), 2);
            out("tunnel-split-write", head + "|" + hex(echo), hex(up.await(2)));
            s.close();
        } finally {
            srv.stop();
            up.close();
        }
    }

    /* ------------------------------------------------------------ http 槽 */

    private static void httpGet() throws Exception {
        HttpUp up = new HttpUp();
        InjectServer srv = httpServer(up.port);
        try {
            Socket s = client(srv.port);
            OutputStream out = s.getOutputStream();
            out.write(("GET http://origin.example/a/b?q=1 HTTP/1.1\r\nHost: origin.example\r\n"
                    + "X-Online-Host: origin.example\r\nUser-Agent: ua\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String resp = readHead(s.getInputStream());
            byte[] body = readN(s.getInputStream(), 5);
            out("http-get", resp + "|" + hex(body), up.awaitHead());
            s.close();
        } finally {
            srv.stop();
            up.close();
        }
    }

    private static void httpKeepAlive() throws Exception {
        HttpUp up = new HttpUp();
        InjectServer srv = httpServer(up.port);
        try {
            Socket s = client(srv.port);
            OutputStream out = s.getOutputStream();
            out.write(("GET http://origin.example/1 HTTP/1.1\r\nHost: origin.example\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String r1 = readHead(s.getInputStream());
            readN(s.getInputStream(), 5);
            out.write(("GET http://origin.example/2 HTTP/1.1\r\nHost: origin.example\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String r2 = readHead(s.getInputStream());
            readN(s.getInputStream(), 5);
            out("http-keepalive", r1 + "|" + r2, up.awaitHeads(2));
            s.close();
        } finally {
            srv.stop();
            up.close();
        }
    }

    /** body 里出现 "GET " 不能被当成新请求改写。 */
    private static void httpPostBody() throws Exception {
        HttpUp up = new HttpUp();
        InjectServer srv = httpServer(up.port);
        try {
            Socket s = client(srv.port);
            OutputStream out = s.getOutputStream();
            String body = "x=GET /not-a-request HTTP/1.1\r\n\r\n";
            out.write(("POST http://origin.example/p HTTP/1.1\r\nHost: origin.example\r\n"
                    + "Content-Length: " + body.length() + "\r\n\r\n" + body)
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String resp = readHead(s.getInputStream());
            readN(s.getInputStream(), 5);
            out("http-post-body", resp, up.awaitHead());
            s.close();
        } finally {
            srv.stop();
            up.close();
        }
    }

    /** http_del 去掉 Host，模板补回一个：只应剩下一个。 */
    private static void httpDelHeaders() throws Exception {
        HttpUp up = new HttpUp();
        InjectServer srv = httpServer(up.port);
        try {
            Socket s = client(srv.port);
            OutputStream out = s.getOutputStream();
            out.write(("GET http://origin.example/x HTTP/1.1\r\nHost: origin.example\r\n"
                    + "X-Online-Host: origin.example\r\nKeep-Alive: timeout=5\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String resp = readHead(s.getInputStream());
            readN(s.getInputStream(), 5);
            out("http-del", resp, up.awaitHead());
            s.close();
        } finally {
            srv.stop();
            up.close();
        }
    }

    /* ------------------------------------------------------------ 装配 */

    private static InjectServer tunnelServer() throws Exception {
        Ini c = new Ini();
        c.httpsOn = false;          /* 没有网关 → 直连目标 */
        c.httpOn = false;
        InjectServer s = new InjectServer(c, new HttpDns());
        s.start(0);
        return s;
    }

    private static InjectServer httpServer(int upPort) throws Exception {
        Ini c = new Ini();
        c.httpOn = true;
        c.httpDirect = false;
        c.httpIp = "127.0.0.1";
        c.httpPort = upPort;
        c.httpFirst = "[M] [U] [V]\r\nHost: [H]\r\nX-Inject: 1";
        c.httpDel = "Host,X-Online-Host,Keep-Alive";
        c.httpsOn = false;
        InjectServer s = new InjectServer(c, new HttpDns());
        s.start(0);
        return s;
    }

    private static Socket client(int port) throws IOException {
        Socket s = new Socket();
        s.connect(new InetSocketAddress("127.0.0.1", port), 3000);
        s.setSoTimeout(5000);
        s.setTcpNoDelay(true);
        return s;
    }

    /* ------------------------------------------------------------ 上游 */

    static final class EchoUp implements Runnable {
        final ServerSocket ss;
        final int port;
        final ByteArrayOutputStream got = new ByteArrayOutputStream();
        Socket peer;

        EchoUp() throws IOException {
            ss = new ServerSocket(0);
            port = ss.getLocalPort();
            Thread t = new Thread(this, "echo-up");
            t.setDaemon(true);
            t.start();
        }

        public void run() {
            try {
                peer = ss.accept();
                InputStream in = peer.getInputStream();
                OutputStream out = peer.getOutputStream();
                byte[] b = new byte[4096];
                int r;
                while ((r = in.read(b)) > 0) {
                    got.write(b, 0, r);
                    out.write(b, 0, r);
                    out.flush();
                }
            } catch (Exception ignored) {
            }
        }

        void send(byte[] b) throws IOException {
            for (int i = 0; i < 100 && peer == null; i++) {
                try { Thread.sleep(20); } catch (InterruptedException ignored) { }
            }
            peer.getOutputStream().write(b);
            peer.getOutputStream().flush();
        }

        synchronized byte[] await(int want) throws Exception {
            for (int i = 0; i < 100 && got.size() < want; i++) Thread.sleep(20);
            return got.toByteArray();
        }

        void close() throws IOException {
            ss.close();
            if (peer != null) peer.close();
        }
    }

    /** 记录收到的每个请求头，回固定的 200 + 5 字节 body。 */
    static final class HttpUp implements Runnable {
        final ServerSocket ss;
        final int port;
        final StringBuilder heads = new StringBuilder();
        volatile int headCount;
        Socket peer;

        HttpUp() throws IOException {
            ss = new ServerSocket(0);
            port = ss.getLocalPort();
            Thread t = new Thread(this, "http-up");
            t.setDaemon(true);
            t.start();
        }

        public void run() {
            try {
                peer = ss.accept();
                InputStream in = peer.getInputStream();
                OutputStream out = peer.getOutputStream();
                ByteArrayOutputStream cur = new ByteArrayOutputStream();
                byte[] one = new byte[1];
                while (true) {
                    int r = in.read(one);
                    if (r <= 0) break;
                    cur.write(one[0]);
                    byte[] a = cur.toByteArray();
                    int L = a.length;
                    if (L >= 4 && a[L - 4] == '\r' && a[L - 3] == '\n'
                            && a[L - 2] == '\r' && a[L - 1] == '\n') {
                        heads.append(new String(a, StandardCharsets.ISO_8859_1).replace("\r\n", "\\n"))
                                .append("||");
                        headCount++;
                        cur.reset();
                        out.write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
                                .getBytes(StandardCharsets.ISO_8859_1));
                        out.flush();
                    }
                }
            } catch (Exception ignored) {
            }
        }

        synchronized String awaitHead() throws Exception {
            for (int i = 0; i < 100 && headCount < 1; i++) Thread.sleep(20);
            return heads.toString().replace("" + '|' + '|', "||");
        }

        synchronized String awaitHeads(int want) throws Exception {
            for (int i = 0; i < 100 && headCount < want; i++) Thread.sleep(20);
            return heads.toString();
        }

        void close() throws IOException {
            ss.close();
            if (peer != null) peer.close();
        }
    }

    /* ------------------------------------------------------------ 工具 */

    private static String readHead(InputStream in) throws IOException {
        StringBuilder b = new StringBuilder();
        int st = 0;
        while (b.length() < 16384) {
            int c = in.read();
            if (c < 0) break;
            b.append((char) c);
            if (c == '\r' && (st == 0 || st == 2)) st++;
            else if (c == '\n' && (st == 1 || st == 3)) st++;
            else st = c == '\r' ? 1 : 0;
            if (st == 4) break;
        }
        return b.toString().replace("\r\n", "\\n");
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        int got = 0;
        while (got < n) {
            int r = in.read(b, got, n - got);
            if (r < 0) break;
            got += r;
        }
        byte[] out = new byte[got];
        System.arraycopy(b, 0, out, 0, got);
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    private static void out(String name, String client, String upstream) {
        System.out.println(String.format("%03d", n++) + "-" + name + "\tC=" + client + "\tU=" + upstream);
    }
}
