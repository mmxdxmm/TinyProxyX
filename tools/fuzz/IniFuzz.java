package com.lcs.tproxy.inject;

/** 差分对拍：同一批脏输入分别喂给 1.8.2 与 2.0.0 的 Ini.parse，逐字段比对。 */
public final class IniFuzz {

    private static final String[] KEYS = {
            "listen_port", "local_ip", "http_others", "http_direct", "http_ip", "http_port",
            "http_first", "http_del", "http_delate", "https_connect", "https_direct", "https_ip",
            "https_port", "https_first", "https_del", "https_delate", "inject_fallback",
            "dns_tcp", "dns_url", "dns_ip", "dns_port", "dns_listen_port", "name", "remarks",
            "apn", "v2ray_domain", "conf_model", "unknown_key",
    };

    private static final String[] VALS = {
            "", " ", "on", "off", "true", "1", "yes", "80", "443", "0", "-1", "abc",
            "1.2.3.4", "dns.example.com", "\"quoted\"", "'single'", "a;b", "x#y", "a=b",
            "\\r\\n", "a\\tb", "  spaced  ", "\u4e2d\u6587", "CONNECT [H] HTTP/1.1\r\n\r\n",
            ";", "#", "=", "\t",
    };

    private static String pick(java.util.Random r, String[] a) {
        return a[r.nextInt(a.length)];
    }

    private static String esc(String s) {
        if (s == null) return "<null>";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r') b.append("\\r");
            else if (c == '\n') b.append("\\n");
            else if (c == '\t') b.append("\\t");
            else b.append(c);
        }
        return b.toString();
    }

    public static void main(String[] a) {
        java.util.Random r = new java.util.Random(20261102L);
        StringBuilder out = new StringBuilder(1 << 20);
        for (int n = 0; n < 20000; n++) {
            StringBuilder src = new StringBuilder();
            int lines = r.nextInt(6);
            for (int l = 0; l < lines; l++) {
                int mode = r.nextInt(10);
                if (mode == 0) {
                    src.append("  ");
                } else if (mode == 1) {
                    src.append("# comment ").append(pick(r, VALS));
                } else if (mode == 2) {
                    src.append(pick(r, KEYS)).append('=').append(pick(r, VALS)).append("  # tail");
                } else if (mode == 3) {
                    src.append(' ').append(pick(r, KEYS)).append(" = ").append(pick(r, VALS)).append(' ');
                } else if (mode == 4) {
                    src.append("=").append(pick(r, VALS));
                } else if (mode == 5) {
                    src.append(pick(r, VALS));
                } else {
                    src.append(pick(r, KEYS)).append('=')
                            .append(pick(r, VALS)).append(';');
                }
                src.append(r.nextBoolean() ? "\r\n" : r.nextBoolean() ? "\n" : "\r");
            }
            Ini c = Ini.parse(src.toString());
            out.append(esc(c.raw)).append('|').append(c.listenPort).append('|').append(esc(c.localIp))
                    .append('|').append(esc(c.httpIp)).append('|').append(c.httpPort)
                    .append('|').append(esc(c.httpFirst)).append('|').append(esc(c.httpDel))
                    .append('|').append(c.httpOn).append('|').append(c.httpDirect)
                    .append('|').append(c.httpDispose)
                    .append('|').append(esc(c.httpsIp)).append('|').append(c.httpsPort)
                    .append('|').append(esc(c.httpsFirst)).append('|').append(esc(c.httpsDel))
                    .append('|').append(c.httpsOn).append('|').append(c.httpsDirect)
                    .append('|').append(c.httpsDispose)
                    .append('|').append(c.injectFallback).append('|').append(c.httpFallbackHttps)
                    .append('|').append(esc(c.dnsTcp)).append('|').append(esc(c.dnsUrl))
                    .append('|').append(esc(c.dnsIp)).append('|').append(c.dnsPort)
                    .append('|').append(c.dnsListenPort)
                    .append('|').append(esc(c.name)).append('|').append(esc(c.apn))
                    .append('|').append(esc(c.v2rayDomain)).append('|').append(esc(c.confModel))
                    .append('\n');
        }
        System.out.print(out);
    }
}
