package com.lcs.tproxy.inject;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

/** 最小复现：CONNECT 头后紧跟数据，看上游到底收到什么。 */
public final class Early {
    public static void main(String[] a) throws Exception {
        final ServerSocket ss = new ServerSocket(0);
        final ByteArrayOutputStream got = new ByteArrayOutputStream();
        Thread up = new Thread(new Runnable() {
            public void run() {
                try {
                    Socket p = ss.accept();
                    InputStream in = p.getInputStream();
                    OutputStream out = p.getOutputStream();
                    byte[] b = new byte[1024];
                    int r;
                    while ((r = in.read(b)) > 0) {
                        got.write(b, 0, r);
                        out.write(b, 0, r);
                        out.flush();
                    }
                } catch (Exception e) {
                    System.out.println("UP ERR " + e);
                }
            }
        });
        up.setDaemon(true);
        up.start();

        Ini c = new Ini();
        c.httpsOn = false;
        c.httpOn = false;
        InjectServer srv = new InjectServer(c, new HttpDns(), new InjectServer.LogSink() {
            public void log(String line) { System.out.println("LOG " + line); }
        });
        int port = srv.start(0);
        System.out.println("PORT " + port);

        Socket s = new Socket("127.0.0.1", port);
        s.setSoTimeout(3000);
        OutputStream out = s.getOutputStream();
        out.write(("CONNECT 127.0.0.1:" + ss.getLocalPort()
                + " HTTP/1.1\r\nHost: h\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        out.write("EARLY-DATA-0123456789".getBytes(StandardCharsets.ISO_8859_1));
        out.flush();

        /* 读响应头 */
        StringBuilder h = new StringBuilder();
        int st = 0;
        try {
            while (h.length() < 4096) {
                int ch = s.getInputStream().read();
                if (ch < 0) break;
                h.append((char) ch);
                if (ch == '\r' && (st == 0 || st == 2)) st++;
                else if (ch == '\n' && (st == 1 || st == 3)) st++;
                else st = ch == '\r' ? 1 : 0;
                if (st == 4) break;
            }
        } catch (Exception e) {
            System.out.println("HEAD ERR " + e);
        }
        System.out.println("HEAD=[" + h.toString().replace("\r\n", "\\n") + "]");

        byte[] echo = new byte[21];
        int n = 0;
        try {
            while (n < 21) {
                int r = s.getInputStream().read(echo, n, 21 - n);
                if (r < 0) break;
                n += r;
            }
        } catch (Exception e) {
            System.out.println("ECHO ERR " + e + " n=" + n);
        }
        Thread.sleep(200);
        System.out.println("CLIENT GOT " + n + " bytes");
        System.out.println("UP GOT " + got.size() + " [" + new String(got.toByteArray(), StandardCharsets.ISO_8859_1) + "]");
        System.out.println("LAST ERROR " + srv.lastError);
        srv.stop();
        ss.close();
    }
}
