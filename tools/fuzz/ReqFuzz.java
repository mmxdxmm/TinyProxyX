package com.lcs.tproxy.inject;

import java.lang.reflect.Method;

/** 差分对拍：随机请求头分别走 1.8.2 的 Req.of(String) 与 2.0.0 的 Req.of(byte[],int)。 */
public final class ReqFuzz {

    private static final String[] METHODS = {"CONNECT", "connect", "GET", "get", "POST", "HEAD",
            "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "FOO", ""};
    private static final String[] HOSTS = {"a.com", "a.com:8080", "1.2.3.4:443", "[::1]:443",
            "[2001:db8::1]", "user@a.com:80", "a.com.", "localhost", "", "a_b.com:0"};
    private static final String[] PATHS = {"/", "/a/b?c=d", "*", "http://a.com/x", "https://a.com:8443/y?z=1"};
    private static final String[] NAMES = {"Host", "host", "HOST", "X-Online-Host", "Host ", " Host",
            "Content-Length", "Transfer-Encoding", "X", ""};
    private static final String[] VALS = {"", " ", "a.com", "  a.com:81  ", "chunked", "0", "12",
            "[::1]:443", "\tq\t", "a b"};

    private static String pick(java.util.Random r, String[] a) {
        return a[r.nextInt(a.length)];
    }

    private static String esc(String s) {
        if (s == null) return "<null>";
        return s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }

    private static Method find(String name, Class<?>... sig) {
        try {
            Method m = InjectServer.Req.class.getDeclaredMethod(name, sig);
            m.setAccessible(true);
            return m;
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String[] a) throws Exception {
        Method bytes = find("of", byte[].class, int.class);
        Method text = find("of", String.class);
        java.util.Random r = new java.util.Random(778899L);
        StringBuilder out = new StringBuilder(1 << 20);
        for (int n = 0; n < 20000; n++) {
            StringBuilder s = new StringBuilder();
            String m = pick(r, METHODS);
            String t = pick(r, PATHS);
            int shape = r.nextInt(8);
            if (shape == 0) {
                s.append(m);
            } else if (shape == 1) {
                s.append(m).append(' ').append(t);
            } else if (shape == 2) {
                s.append(m).append(' ').append(t).append(' ').append("HTTP/1.1");
            } else {
                s.append(m).append(' ').append(t).append(' ').append("HTTP/1.1\r\n");
            }
            int heads = r.nextInt(5);
            for (int h = 0; h < heads; h++) {
                String name = pick(r, NAMES);
                String val = pick(r, VALS);
                s.append(name);
                if (r.nextInt(6) != 0) s.append(':');
                s.append(r.nextBoolean() ? " " : "");
                s.append(val);
                s.append("\r\n");
            }
            if (r.nextInt(4) != 0) s.append("\r\n");
            String input = s.toString();
            Object req;
            if (bytes != null) {
                byte[] b = input.getBytes("ISO-8859-1");
                req = bytes.invoke(null, b, b.length);
            } else {
                req = text.invoke(null, input);
            }
            InjectServer.Req q = (InjectServer.Req) req;
            out.append(esc(q.method)).append('|').append(esc(q.target)).append('|')
                    .append(esc(q.version)).append('|').append(esc(q.hostHeader)).append('|')
                    .append(esc(q.host)).append('|').append(q.port).append('|')
                    .append(q.tunnel()).append('|').append(esc(input)).append('\n');
        }
        System.out.print(out);
    }
}
