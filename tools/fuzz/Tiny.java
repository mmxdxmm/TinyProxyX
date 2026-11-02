package com.lcs.tproxy.inject;

import java.io.ByteArrayInputStream;
import java.io.PushbackInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/** 单独验证 readHead 的块读 + 回退。 */
public final class Tiny {
    public static void main(String[] a) throws Exception {
        Method m = InjectServer.class.getDeclaredMethod("readHead", PushbackInputStream.class);
        m.setAccessible(true);

        byte[] data = "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: h\r\n\r\nEARLY-DATA-0123456789"
                .getBytes(StandardCharsets.ISO_8859_1);
        PushbackInputStream in = new PushbackInputStream(new ByteArrayInputStream(data), 8192);
        byte[] head = (byte[]) m.invoke(null, in);
        System.out.println("head=" + (head == null ? "null" : head.length + " ["
                + new String(head, StandardCharsets.ISO_8859_1).replace("\r\n", "\\n") + "]"));

        byte[] rest = new byte[64];
        int n = in.read(rest);
        System.out.println("rest=" + n + " [" + new String(rest, 0, Math.max(0, n),
                StandardCharsets.ISO_8859_1) + "]");

        StringBuilder sb = new StringBuilder("CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\nCookie: ");
        for (int i = 0; i < 1200; i++) sb.append((char) ('a' + i % 26));
        sb.append("\r\n\r\nTAIL");
        byte[] big = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        PushbackInputStream in2 = new PushbackInputStream(new ByteArrayInputStream(big), 8192);
        byte[] h2 = (byte[]) m.invoke(null, in2);
        System.out.println("big head=" + (h2 == null ? "null" : h2.length + " tail=["
                + new String(h2, Math.max(0, h2.length - 12), Math.min(12, h2.length),
                StandardCharsets.ISO_8859_1).replace("\r\n", "\\n") + "]"));
        byte[] r2 = new byte[64];
        int n2 = in2.read(r2);
        System.out.println("big rest=" + n2 + " [" + new String(r2, 0, Math.max(0, n2),
                StandardCharsets.ISO_8859_1) + "]");
    }
}
