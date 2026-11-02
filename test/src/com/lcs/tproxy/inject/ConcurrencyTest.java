package com.lcs.tproxy.inject;

import com.lcs.tproxy.model.Profile;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/** 并发冒烟：200 条并发 CONNECT + 300 次短连接，确认线程池化之后功能不变、不丢连接。 */
public final class ConcurrencyTest {

    private static final AtomicInteger okCount = new AtomicInteger();
    private static final AtomicInteger badCount = new AtomicInteger();
    private static volatile String firstError = "";

    /** 回显服务：收到什么原样吐回。 */
    static final class Echo {
        private final ServerSocket ss;

        Echo() throws Exception {
            ss = new ServerSocket(0, 256);
            Thread t = new Thread(new Runnable() {
                public void run() {
                    while (!ss.isClosed()) {
                        try {
                            final Socket c = ss.accept();
                            Thread w = new Thread(new Runnable() {
                                public void run() {
                                    try {
                                        InputStream in = c.getInputStream();
                                        OutputStream out = c.getOutputStream();
                                        byte[] b = new byte[512];
                                        int n;
                                        while ((n = in.read(b)) > 0) {
                                            out.write(b, 0, n);
                                            out.flush();
                                        }
                                    } catch (Exception ignored) {
                                    } finally {
                                        try {
                                            c.close();
                                        } catch (Exception ignored) {
                                        }
                                    }
                                }
                            });
                            w.setDaemon(true);
                            w.start();
                        } catch (Exception e) {
                            return;
                        }
                    }
                }
            }, "echo-accept");
            t.setDaemon(true);
            t.start();
        }

        int port() {
            return ss.getLocalPort();
        }

        void close() {
            try {
                ss.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static String readHead(InputStream in) throws Exception {
        StringBuilder b = new StringBuilder();
        int state = 0;
        while (b.length() < 8192) {
            int c = in.read();
            if (c < 0) break;
            b.append((char) c);
            state = (c == '\r' && (state == 0 || state == 2)) ? state + 1
                    : (c == '\n' && (state == 1 || state == 3)) ? state + 1 : 0;
            if (state == 4) break;
        }
        return b.toString();
    }

    private static void one(int port, int echoPort, int id) {
        Socket s = null;
        try {
            s = new Socket("127.0.0.1", port);
            s.setSoTimeout(10000);
            OutputStream out = s.getOutputStream();
            String tag = "PING" + id + "-" + System.nanoTime();
            out.write(("CONNECT 127.0.0.1:" + echoPort + " HTTP/1.1\r\nHost: 127.0.0.1:"
                    + echoPort + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            if (!readHead(s.getInputStream()).startsWith("HTTP/1.1 200")) {
                throw new IllegalStateException("no 200");
            }
            out.write(tag.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            byte[] want = tag.getBytes(StandardCharsets.ISO_8859_1);
            byte[] got = new byte[want.length];
            int n = 0;
            InputStream in = s.getInputStream();
            while (n < got.length) {
                int r = in.read(got, n, got.length - n);
                if (r <= 0) break;
                n += r;
            }
            if (n != want.length) throw new IllegalStateException("short echo " + n);
            for (int i = 0; i < want.length; i++) {
                if (want[i] != got[i]) throw new IllegalStateException("echo mismatch");
            }
            okCount.incrementAndGet();
        } catch (Exception e) {
            badCount.incrementAndGet();
            if (firstError.length() == 0) firstError = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            try {
                if (s != null) s.close();
            } catch (Exception ignored) {
            }
        }
    }

    public static void main(String[] a) throws Exception {
        Echo echo = new Echo();
        Ini c = new Ini();
        c.httpsIp = "";
        c.httpIp = "";
        HttpDns dns = new HttpDns();
        dns.policy = Profile.DNS_DIRECT;
        InjectServer srv = new InjectServer(c, dns);
        final int port = srv.start(0);
        final int echoPort = echo.port();

        /* 1) 200 条同时压进来 */
        final int N = 200;
        final CountDownLatch gate = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(N);
        for (int i = 0; i < N; i++) {
            final int id = i;
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        gate.await();
                        one(port, echoPort, id);
                    } catch (Exception e) {
                        badCount.incrementAndGet();
                    } finally {
                        done.countDown();
                    }
                }
            }, "load-" + i);
            t.setDaemon(true);
            t.start();
        }
        gate.countDown();
        done.await();

        int parOk = okCount.get();
        int parBad = badCount.get();

        /* 2) 300 次短连接（顺序）——线程池复用的目标场景 */
        okCount.set(0);
        badCount.set(0);
        long t0 = System.nanoTime();
        for (int i = 0; i < 300; i++) one(port, echoPort, 10000 + i);
        long ms = (System.nanoTime() - t0) / 1000000L;
        int seqOk = okCount.get();
        int seqBad = badCount.get();

        srv.stop();
        echo.close();

        int live = 0;
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if (t.getName().startsWith("inj-")) live++;
        }
        System.out.println("parallel ok=" + parOk + "/" + N + " bad=" + parBad);
        System.out.println("sequential ok=" + seqOk + "/300 bad=" + seqBad + " in " + ms + " ms");
        System.out.println("injector threads alive=" + live);
        boolean pass = parOk == N && parBad == 0 && seqOk == 300 && seqBad == 0;
        System.out.println(pass ? "CONCURRENCY OK" : "CONCURRENCY FAIL " + firstError);
        if (!pass) System.exit(1);
    }
}
