package com.lcs.tproxy.model;

/**
 * 一张常量表，替代散落在各处的字符串比较链。
 *
 * <p>协议、传输、TLS 形态、路由策略、规则字段在解析边界（{@code Node.fromJson}、
 * {@code Profile.fromJson}、链接导入）各算一次整数 id，之后所有分派都走数组下标或
 * tableswitch —— 不再对同一串字符做七八次 equals。
 *
 * <p>字符串仍然是序列化格式（老存档必须能读），运行期只认 id。
 */
public final class Kinds {

    /* ---------------- 协议 ---------------- */
    public static final int VLESS = 0;
    public static final int VMESS = 1;
    public static final int TROJAN = 2;
    public static final int SS = 3;
    public static final int SOCKS = 4;
    public static final int HTTP = 5;
    public static final int INJECT = 6;
    public static final int UNKNOWN = 7;
    public static final int TYPE_N = 8;

    public static final String[] TYPE = {"vless", "vmess", "trojan", "ss", "socks", "http", "inject", ""};

    /** 能承载 UDP 的 xray 出站：http 只支持 TCP，注入节点不能再嵌套。 */
    private static final boolean[] UDP_CAPABLE = {true, true, true, true, true, false, false, false};

    /* ---------------- 传输 ---------------- */
    public static final int NET_TCP = 0;
    public static final int NET_WS = 1;
    public static final int NET_GRPC = 2;
    public static final int NET_H2 = 3;
    public static final int NET_HTTP = 4;
    public static final int NET_QUIC = 5;
    public static final int NET_HTTPUPGRADE = 6;
    public static final int NET_XHTTP = 7;
    public static final int NET_KCP = 8;
    public static final int NET_UNKNOWN = 9;
    public static final int NET_N = 10;

    public static final String[] NET = {"tcp", "ws", "grpc", "h2", "http", "quic",
            "httpupgrade", "xhttp", "kcp", ""};

    /* ---------------- TLS 形态 ---------------- */
    public static final int SEC_NONE = 0;
    public static final int SEC_TLS = 1;
    public static final int SEC_REALITY = 2;
    public static final int SEC_UNKNOWN = 3;
    public static final int SEC_N = 4;

    /* ---------------- 三态策略 ---------------- */
    public static final int POL_BLOCK = 0;
    public static final int POL_PROXY = 1;
    public static final int POL_DIRECT = 2;
    public static final int POL_BAD = 3;
    public static final int POL_N = 4;

    public static final String[] POLICY = {"block", "proxy", "direct", ""};

    /* ---------------- 规则字段 ---------------- */
    public static final int F_DOMAIN = 0;
    public static final int F_DOMAIN_SUFFIX = 1;
    public static final int F_DOMAIN_KEYWORD = 2;
    public static final int F_DOMAIN_REGEX = 3;
    public static final int F_GEOSITE = 4;
    public static final int F_IP = 5;
    public static final int F_GEOIP = 6;
    public static final int F_PORT = 7;
    public static final int F_PROCESS = 8;
    public static final int F_INBOUND = 9;
    public static final int F_NETWORK = 10;
    public static final int F_UNKNOWN = 11;
    public static final int F_N = 12;

    /* ---------------- 规则动作 ---------------- */
    public static final int A_PROXY = 0;
    public static final int A_DIRECT = 1;
    public static final int A_BLOCK = 2;

    private Kinds() {
    }

    /** 解析边界用一次；之后统一走 {@link Node#kind()} 的缓存。 */
    public static int type(String s) {
        if (s == null) return UNKNOWN;
        switch (s.length()) {
            case 2:
                return "ss".equals(s) ? SS : UNKNOWN;
            case 4:
                return "http".equals(s) ? HTTP : UNKNOWN;
            case 5:
                if ("vless".equals(s)) return VLESS;
                if ("vmess".equals(s)) return VMESS;
                if ("socks".equals(s)) return SOCKS;
                return UNKNOWN;
            case 6:
                if ("trojan".equals(s)) return TROJAN;
                if ("inject".equals(s)) return INJECT;
                return UNKNOWN;
            /* xray 自己的协议名，导入完整配置时会遇到；内部统一成 ss。 */
            case 11:
                return "shadowsocks".equals(s) ? SS : UNKNOWN;
            default:
                return UNKNOWN;
        }
    }

    public static int net(String s) {
        if (s == null || s.length() == 0) return NET_TCP;
        switch (s.length()) {
            case 2:
                if ("ws".equals(s)) return NET_WS;
                if ("h2".equals(s)) return NET_H2;
                return NET_UNKNOWN;
            case 3:
                if ("tcp".equals(s)) return NET_TCP;
                if ("kcp".equals(s)) return NET_KCP;
                return NET_UNKNOWN;
            case 4:
                if ("grpc".equals(s)) return NET_GRPC;
                if ("http".equals(s)) return NET_HTTP;
                if ("quic".equals(s)) return NET_QUIC;
                return NET_UNKNOWN;
            case 5:
                return "xhttp".equals(s) ? NET_XHTTP : NET_UNKNOWN;
            case 11:
                return "httpupgrade".equals(s) ? NET_HTTPUPGRADE : NET_UNKNOWN;
            default:
                return NET_UNKNOWN;
        }
    }

    public static int security(String s) {
        if (s == null || s.length() == 0) return SEC_NONE;
        switch (s.length()) {
            case 3:
                return "tls".equals(s) ? SEC_TLS : SEC_UNKNOWN;
            case 4:
                return "none".equals(s) ? SEC_NONE : SEC_UNKNOWN;
            case 7:
                return "reality".equals(s) ? SEC_REALITY : SEC_UNKNOWN;
            default:
                return SEC_UNKNOWN;
        }
    }

    /** 非法值一律落到默认档，和原来 policy(v, def) 的语义一致。 */
    public static int policy(String v, int def) {
        if (v == null) return def;
        switch (v.length()) {
            case 5:
                if ("block".equals(v)) return POL_BLOCK;
                if ("proxy".equals(v)) return POL_PROXY;
                return def;
            case 6:
                return "direct".equals(v) ? POL_DIRECT : def;
            default:
                return def;
        }
    }

    /** 输入是 Rule 的序列化值（snake_case），不是 xray 的 JSON 键名。 */
    public static int field(String s) {
        if (s == null) return F_UNKNOWN;
        switch (s.length()) {
            case 2:
                return "ip".equals(s) ? F_IP : F_UNKNOWN;
            case 4:
                return "port".equals(s) ? F_PORT : F_UNKNOWN;
            case 5:
                return "geoip".equals(s) ? F_GEOIP : F_UNKNOWN;
            case 6:
                return "domain".equals(s) ? F_DOMAIN : F_UNKNOWN;
            case 7:
                if ("geosite".equals(s)) return F_GEOSITE;
                if ("process".equals(s)) return F_PROCESS;
                if ("network".equals(s)) return F_NETWORK;
                if ("inbound".equals(s)) return F_INBOUND;
                return F_UNKNOWN;
            case 12:
                return "domain_regex".equals(s) ? F_DOMAIN_REGEX : F_UNKNOWN;
            case 13:
                return "domain_suffix".equals(s) ? F_DOMAIN_SUFFIX : F_UNKNOWN;
            case 14:
                return "domain_keyword".equals(s) ? F_DOMAIN_KEYWORD : F_UNKNOWN;
            default:
                return F_UNKNOWN;
        }
    }

    public static boolean udpCapable(int kind) {
        return UDP_CAPABLE[kind];
    }

    public static String typeName(int kind) {
        return TYPE[kind];
    }
}
