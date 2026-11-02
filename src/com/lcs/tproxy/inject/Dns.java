package com.lcs.tproxy.inject;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

/** Minimal DNS wire codec: build an A/AAAA query, pull the first answer, answer a query. */
public class Dns {

    public static final int A = 1;
    public static final int AAAA = 28;

    private static final byte[] HEADER = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    public static byte[] query(String host, int type) {
        /* 上限按 UTF-8 最坏 3 倍预留，最后按实际长度裁掉：一次分配，不扩容。 */
        byte[] out = new byte[12 + host.length() * 3 + 8];
        System.arraycopy(HEADER, 0, out, 0, 12);
        int p = 12;
        int start = 0;
        for (int i = 0; i <= host.length(); i++) {
            if (i < host.length() && host.charAt(i) != '.') continue;
            byte[] s = host.substring(start, i).getBytes(StandardCharsets.UTF_8);
            out[p++] = (byte) s.length;
            if (s.length > 0) {
                System.arraycopy(s, 0, out, p, s.length);
                p += s.length;
            }
            start = i + 1;
        }
        out[p++] = 0;
        out[p++] = (byte) (type >> 8);
        out[p++] = (byte) type;
        out[p++] = 0;
        out[p++] = 1;
        return p == out.length ? out : java.util.Arrays.copyOf(out, p);
    }

    public static String firstA(byte[] r) {
        byte[] raw = firstRaw(r, A, 4);
        return raw == null ? null : (raw[0] & 0xFF) + "." + (raw[1] & 0xFF) + "."
                + (raw[2] & 0xFF) + "." + (raw[3] & 0xFF);
    }

    /** First AAAA answer as a literal, or null. v6-only 域名只有 AAAA，只问 A 永远是空。 */
    public static String firstAAAA(byte[] r) {
        byte[] raw = firstRaw(r, AAAA, 16);
        if (raw == null) return null;
        try {
            return InetAddress.getByAddress(raw).getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

    /** First record of {@code wantType}. CNAME 之类直接跳过；压缩名按指针的 2 字节前进。 */
    private static byte[] firstRaw(byte[] r, int wantType, int wantLen) {
        if (r == null || r.length < 12) return null;
        int off = 12;
        int qd = ((r[4] & 0xFF) << 8) | (r[5] & 0xFF);
        /* 问题段一般只有 1 条；展开 2 条一轮，减少循环回边。 */
        int i = 0;
        while (i + 1 < qd) {
            off = skipName(r, off) + 4;
            off = skipName(r, off) + 4;
            i += 2;
        }
        if (i < qd) off = skipName(r, off) + 4;

        int an = ((r[6] & 0xFF) << 8) | (r[7] & 0xFF);
        byte[] buf = new byte[wantLen];
        i = 0;
        while (i + 1 < an) {
            int next = consume(r, off, wantType, wantLen, buf);
            if (next < 0) return copy(buf, wantLen);
            next = consume(r, next, wantType, wantLen, buf);
            if (next < 0) return copy(buf, wantLen);
            off = next;
            i += 2;
        }
        if (i < an) {
            int next = consume(r, off, wantType, wantLen, buf);
            if (next < 0) return copy(buf, wantLen);
        }
        return null;
    }

    private static byte[] copy(byte[] buf, int n) {
        byte[] out = new byte[n];
        System.arraycopy(buf, 0, out, 0, n);
        return out;
    }

    /** 读一条资源记录：命中返回负数（下一条起点取反），否则返回下一条起点。 */
    private static int consume(byte[] r, int off, int wantType, int wantLen, byte[] buf) {
        off = skipName(r, off);
        if (off + 10 > r.length) return r.length;
        int type = ((r[off] & 0xFF) << 8) | (r[off + 1] & 0xFF);
        int rdlen = ((r[off + 8] & 0xFF) << 8) | (r[off + 9] & 0xFF);
        int data = off + 10;
        int next = data + rdlen;
        if (type != wantType || rdlen != wantLen || data + wantLen > r.length) return next;
        System.arraycopy(r, data, buf, 0, wantLen);
        return -(next + 1);
    }

    private static int skipName(byte[] r, int off) {
        while (off < r.length) {
            int len = r[off] & 0xFF;
            boolean pointer = (len & 0xC0) == 0xC0;
            off += pointer ? 2 : 1 + len;
            if (pointer || len == 0) break;
        }
        return off;
    }

    /** Answer one query with a record matching its qtype; empty NOERROR when there is none.
     *  null only when the request itself is unusable (we then stay silent). */
    public static byte[] answer(byte[] req, HttpDns dns) {
        if (req == null || req.length < 12) return null;
        int qd = ((req[4] & 0xFF) << 8) | (req[5] & 0xFF);
        if (qd != 1) return null;
        int end = 12;
        StringBuilder name = new StringBuilder();
        while (end < req.length) {
            int len = req[end] & 0xFF;
            if (len == 0) {
                end++;
                break;
            }
            name.append(new String(req, end + 1, len, StandardCharsets.UTF_8)).append('.');
            end += 1 + len;
        }
        if (end + 4 > req.length) return null;
        int qtype = ((req[end] & 0xFF) << 8) | (req[end + 1] & 0xFF);
        String host = name.length() > 0 ? name.substring(0, name.length() - 1) : "";
        String ip = dns.resolve(host);
        byte[] raw = null;
        if (ip != null) {
            try {
                raw = InetAddress.getByName(ip).getAddress();
            } catch (Exception ignored) {
            }
        }
        /* 1 = A, 2 = AAAA, 0 = 没有可回记录。三种状态的答案长度一次算清。 */
        int kind = raw == null ? 0 : (raw.length == 4 && qtype == A) ? 1
                : (raw.length == 16 && qtype == AAAA) ? 2 : 0;
        int qlen = end + 4 - 12;
        int rlen = kind == 0 ? 0 : 12 + raw.length;
        byte[] out = new byte[12 + qlen + rlen];

        out[0] = req[0];
        out[1] = req[1];
        out[2] = (byte) 0x81;
        out[3] = (byte) 0x80;
        out[4] = 0;
        out[5] = 1;
        out[6] = 0;
        out[7] = (byte) (kind == 0 ? 0 : 1);
        /* 问题段整段回显：名字 + 结束符 + qtype + qclass。少回后 4 字节的话，
         * 客户端会把应答段的前两个字节当成 qtype，整个包是坏的。 */
        System.arraycopy(req, 12, out, 12, qlen);
        if (kind != 0) {
            int p = 12 + qlen;
            out[p++] = (byte) 0xC0;       /* 指向问题段的名字 */
            out[p++] = 0x0C;
            out[p++] = 0;
            out[p++] = (byte) (kind == 1 ? A : AAAA);
            out[p++] = 0;
            out[p++] = 1;
            out[p++] = 0;
            out[p++] = 0;
            out[p++] = 0;
            out[p++] = 0x3C;              /* TTL 60s */
            out[p++] = 0;
            out[p++] = (byte) raw.length;
            System.arraycopy(raw, 0, out, p, raw.length);
        }
        return out;
    }
}
