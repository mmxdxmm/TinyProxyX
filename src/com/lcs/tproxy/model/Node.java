package com.lcs.tproxy.model;

import org.json.JSONObject;

/** One proxy hop. A profile is an ordered chain of hops in traffic order:
 *  chain[0] is nearest the device, chain[n-1] is the exit. */
public class Node {
    public static final String VLESS = "vless";
    public static final String VMESS = "vmess";
    public static final String TROJAN = "trojan";
    public static final String SS = "ss";
    public static final String SOCKS = "socks";
    public static final String HTTP = "http";
    /** legacy HTTP injection / 免流 hop, configured by the old key=value ini text */
    public static final String INJECT = "inject";

    public static final String[] TYPES = {VLESS, VMESS, TROJAN, SS, SOCKS, HTTP, INJECT};

    /** 能承载 UDP 的 xray 出站。http 出站只支持 TCP，注入节点本身也不能再嵌套。 */
    public static boolean udpCapable(String type) {
        return Kinds.udpCapable(Kinds.type(type));
    }

    /** UDP 是否走在同一条 TCP 隧道里。只有这种节点才能让「服务器连接先经注入网关」
     *  同时又保住 UDP —— VMess/VLESS 的 UDP 复用 TCP；Trojan/SS 要开 uot 才是；
     *  SOCKS 的 UDP ASSOCIATE 一定是独立 UDP，注入网关带不了。 */
    public static boolean udpOverTcp(Node n) {
        if (n == null) return false;
        switch (n.kind()) {
            case Kinds.VLESS:
            case Kinds.VMESS:
                return true;
            case Kinds.TROJAN:
            case Kinds.SS:
                return n.uot;
            default:
                return false;
        }
    }

    private static final String[] V4_PRIVATE = {"10.", "127.", "169.254.", "192.168."};
    private static final String[] V6_PRIVATE = {"::1", "fc", "fd", "fe8", "fe9", "fea", "feb"};
    private static final String[] LOCAL_SUFFIX = {".local", ".lan", ".internal", ".home",
            ".localdomain", ".test"};

    /** 内网/本机地址判定。Xray 26 起 VLESS / Trojan 明文只允许连这类地址，
     *  公网明文会在配置校验阶段被拒，进程直接起不来。宁可少判也不误判。 */
    public static boolean isPrivateHost(String host) {
        if (host == null) return true;
        String h = host.trim().toLowerCase();
        if (h.length() == 0) return true;
        /* v6 字面量先判：原来「没有点就算内网」会把 2001:db8::1 这类公网地址
         * 也当成内网，明文 VLESS/Trojan 的启动警告因此漏报。 */
        if (h.indexOf(':') >= 0) {
            String v6 = h.replace("[", "").replace("]", "");
            for (String p : V6_PRIVATE) if (v6.startsWith(p)) return true;
            return false;
        }
        if (h.indexOf('.') < 0) return true;          /* localhost / 单标签主机名 */
        for (String p : V4_PRIVATE) if (h.startsWith(p)) return true;
        if (h.startsWith("172.")) {
            int dot = h.indexOf('.', 4);
            int b = octet(h, 4, dot < 0 ? h.length() : dot);
            if (b >= 16 && b <= 31) return true;
        }
        for (String s : LOCAL_SUFFIX) if (h.endsWith(s)) return true;
        return false;
    }

    private static int octet(String s, int from, int to) {
        int v = 0;
        for (int i = from; i < to; i++) {
            int c = s.charAt(i) - '0';
            if (c < 0 || c > 9) return -1;
            v = v * 10 + c;
        }
        return to > from ? v : -1;
    }

    public String type = VLESS;
    public String name = "";
    public String host = "";
    public int port = 443;
    public String uuid = "";
    public String password = "";
    public String method = "aes-256-gcm";
    public String user = "";
    public int alterId = 0;
    /** VMess cipher (v2rayNG "scy"), normally auto. */
    public String vmessScy = "auto";
    /** VMess packet encoding (v2rayNG "pcs"), preserved for round-trip export. */
    public String vmessPcs = "";
    public String flow = "";
    /** none | tls | reality */
    public String security = "none";
    public String sni = "";
    public String alpn = "";
    /** uTLS fingerprint: chrome / firefox / safari / randomized */
    public String fp = "";
    /** reality public key + short id + spider-x */
    public String pbk = "";
    public String sid = "";
    public String spx = "/";
    public boolean allowInsecure = false;
    /** tcp | ws | grpc | h2 | httpupgrade | xhttp | kcp | quic */
    public String net = "tcp";
    public String path = "";
    public String hostHdr = "";
    public String serviceName = "";
    public String headerType = "none";
    /** QUIC 传输自己的加密方式；不再和 TLS 的 sni 抢同一个字段 */
    public String quicSecurity = "none";
    /** shadowsocks / trojan UDP-over-TCP: UDP rides inside the TCP tunnel */
    public boolean uot = false;
    /** raw legacy ini text for INJECT hops */
    public String ini = "";
    public String remark = "";

    /* ---- 注入节点的 UDP 转换（只对单节点的注入配置生效） ----
     * 注入链路本身只能走 TCP，UDP 需要一个真正的 UDP 出站来承载。
     * udpNode 是用户从现有节点里挑的一个副本；udpViaInject=true 时，
     * 该节点的服务器连接先经注入网关（保住免流），false 时直连该节点（低延迟）。
     *
     * 副本会脱离列表单独保存，所以记下来源：列表里的节点被改过（订阅更新、
     * 手改地址/密码）时，启动阶段按 udpSrc* 三条线索把副本同步回最新配置。 */
    public Node udpNode = null;
    public boolean udpViaInject = true;
    /** 来源配置 id；空 = 不是从列表复制来的（旧存档/手工构造），不做同步 */
    public String udpSrcProfile = "";
    /** 来源节点在 chain 里的下标 */
    public int udpSrcIndex = -1;
    /** 复制时来源节点的指纹；和当前值不同就说明列表变了 */
    public String udpSrcFp = "";

    /* 字符串 → id 的缓存。字段仍可被界面直接赋值，所以带一个 key 校验：
     * 只有串真的换了才重算，热路径上就是一次引用比较。 */
    private String kindKey;
    private int kindCache;
    private String netKey;
    private int netCache;
    private String secKey;
    private int secCache;

    public Node() {
    }

    public Node(String type, String host, int port) {
        this.type = type;
        this.host = host;
        this.port = port;
    }

    public int kind() {
        if (type != kindKey) {
            kindCache = Kinds.type(type);
            kindKey = type;
        }
        return kindCache;
    }

    public int netId() {
        if (net != netKey) {
            netCache = Kinds.net(net);
            netKey = net;
        }
        return netCache;
    }

    public int secId() {
        if (security != secKey) {
            secCache = Kinds.security(security);
            secKey = security;
        }
        return secCache;
    }

    public Node copy() {
        Node n = new Node();
        n.type = type;
        n.name = name;
        n.host = host;
        n.port = port;
        n.uuid = uuid;
        n.password = password;
        n.method = method;
        n.user = user;
        n.alterId = alterId;
        n.vmessScy = vmessScy;
        n.vmessPcs = vmessPcs;
        n.flow = flow;
        n.security = security;
        n.sni = sni;
        n.alpn = alpn;
        n.fp = fp;
        n.pbk = pbk;
        n.sid = sid;
        n.spx = spx;
        n.allowInsecure = allowInsecure;
        n.net = net;
        n.path = path;
        n.hostHdr = hostHdr;
        n.serviceName = serviceName;
        n.headerType = headerType;
        n.quicSecurity = quicSecurity;
        n.uot = uot;
        n.ini = ini;
        n.remark = remark;
        n.udpNode = udpNode == null ? null : udpNode.copy();
        n.udpViaInject = udpViaInject;
        n.udpSrcProfile = udpSrcProfile;
        n.udpSrcIndex = udpSrcIndex;
        n.udpSrcFp = udpSrcFp;
        return n;
    }

    public String addr() {
        return host + ":" + port;
    }

    public String title() {
        if (name != null && name.length() > 0) return name;
        return Kinds.TYPE[kind()].toUpperCase() + " " + addr();
    }

    public boolean tls() {
        return secId() == Kinds.SEC_TLS || secId() == Kinds.SEC_REALITY;
    }

    /** hops that need a local listener instead of an xray-native outbound */
    public boolean localHop() {
        return kind() == Kinds.INJECT;
    }

    /** 一行说清这一跳到底是什么。注入节点的 host/port 是空的，光看类型名和 ":443"
     *  什么也看不出来，所以把两类请求各自的去向摊开。 */
    public String summary() {
        if (kind() == Kinds.INJECT) return "注入 · " + injectSummary();
        StringBuilder sb = new StringBuilder(Kinds.TYPE[kind()].toUpperCase());
        sb.append(" · ").append(addr());
        if (netId() != Kinds.NET_TCP) sb.append(" · ").append(net);
        if (tls()) sb.append(" · ").append(security);
        return sb.toString();
    }

    private String injectSummary() {
        com.lcs.tproxy.inject.Ini c = com.lcs.tproxy.inject.Ini.parse(ini);
        String s = "HTTP " + slotText(c.httpOn, c.httpDirect, c.httpIp, c.httpPort, c.httpFirst)
                + " · HTTPS " + slotText(c.httpsOn, c.httpsDirect, c.httpsIp, c.httpsPort, c.httpsFirst);
        if (udpNode != null) s += " · UDP→" + udpNode.addr();
        return s;
    }

    /** 关 / 直连 / 110.242.70.68:443 注入 */
    private static String slotText(boolean on, boolean direct, String ip, int port, String first) {
        if (!on) return "关";
        if (direct || ip == null || ip.length() == 0) return "直连";
        return ip + ":" + port + (first != null && first.length() > 0 ? " 注入" : " 转发");
    }

    /** 节点配置指纹：只覆盖会改变出站行为的字段。用于启动时发现「列表里的节点变了」。 */
    public String fingerprint() {
        StringBuilder b = new StringBuilder(96);
        b.append(type).append('|').append(host).append('|').append(port)
                .append('|').append(uuid).append('|').append(password)
                .append('|').append(method).append('|').append(user)
                .append('|').append(alterId).append('|').append(vmessScy)
                .append('|').append(flow).append('|').append(security)
                .append('|').append(sni).append('|').append(alpn).append('|').append(fp)
                .append('|').append(pbk).append('|').append(sid).append('|').append(spx)
                .append('|').append(allowInsecure).append('|').append(net)
                .append('|').append(path).append('|').append(hostHdr)
                .append('|').append(serviceName).append('|').append(headerType)
                .append('|').append(quicSecurity).append('|').append(uot);
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < b.length(); i++) h = (h ^ b.charAt(i)) * 0x100000001b3L;
        return Long.toHexString(h);
    }

    public JSONObject toJson() {
        JSONObject o = new JSONObject();
        try {
            o.put("type", type);
            o.put("name", name);
            o.put("host", host);
            o.put("port", port);
            o.put("uuid", uuid);
            o.put("password", password);
            o.put("method", method);
            o.put("user", user);
            o.put("alterId", alterId);
            o.put("vmessScy", vmessScy);
            o.put("vmessPcs", vmessPcs);
            o.put("flow", flow);
            o.put("security", security);
            o.put("sni", sni);
            o.put("alpn", alpn);
            o.put("fp", fp);
            o.put("pbk", pbk);
            o.put("sid", sid);
            o.put("spx", spx);
            o.put("allowInsecure", allowInsecure);
            o.put("net", net);
            o.put("path", path);
            o.put("hostHdr", hostHdr);
            o.put("serviceName", serviceName);
            o.put("headerType", headerType);
            o.put("quicSecurity", quicSecurity);
            o.put("uot", uot);
            o.put("ini", ini);
            o.put("remark", remark);
            if (udpNode != null) {
                o.put("udpNode", udpNode.toJson());
                o.put("udpViaInject", udpViaInject);
            }
            if (udpSrcProfile.length() > 0) {
                o.put("udpSrcProfile", udpSrcProfile);
                o.put("udpSrcIndex", udpSrcIndex);
                o.put("udpSrcFp", udpSrcFp);
            }
        } catch (Exception ignored) {
        }
        return o;
    }

    public static Node fromJson(JSONObject o) {
        return fromJson(o, 0);
    }

    /** depth guards a corrupt/hand-edited file that nests udpNode into itself */
    private static Node fromJson(JSONObject o, int depth) {
        Node n = new Node();
        n.type = o.optString("type", VLESS);
        n.name = o.optString("name", "");
        n.host = o.optString("host", "");
        n.port = o.optInt("port", 443);
        n.uuid = o.optString("uuid", "");
        n.password = o.optString("password", "");
        n.method = o.optString("method", "aes-256-gcm");
        n.user = o.optString("user", "");
        n.alterId = o.optInt("alterId", 0);
        n.vmessScy = o.optString("vmessScy", "auto");
        n.vmessPcs = o.optString("vmessPcs", "");
        n.flow = o.optString("flow", "");
        n.security = o.optString("security", "none");
        n.sni = o.optString("sni", "");
        n.alpn = o.optString("alpn", "");
        n.fp = o.optString("fp", "");
        n.pbk = o.optString("pbk", "");
        n.sid = o.optString("sid", "");
        n.spx = o.optString("spx", "/");
        n.allowInsecure = o.optBoolean("allowInsecure", false);
        n.net = o.optString("net", "tcp");
        n.path = o.optString("path", "");
        n.hostHdr = o.optString("hostHdr", "");
        n.serviceName = o.optString("serviceName", "");
        n.headerType = o.optString("headerType", "none");
        n.quicSecurity = o.optString("quicSecurity", "");
        /* 1.8.1 及以前把 QUIC security 塞在 sni 里；读到老存档时搬回来，别把它当 TLS SNI。 */
        if (n.quicSecurity.length() == 0) {
            String old = o.optString("sni", "");
            if ("quic".equals(n.net) && ("none".equals(old) || "aes-128-gcm".equals(old)
                    || "chacha20-poly1305".equals(old))) {
                n.quicSecurity = old;
                n.sni = "";
            } else {
                n.quicSecurity = "none";
            }
        }
        n.uot = o.optBoolean("uot", false);
        n.ini = o.optString("ini", "");
        n.remark = o.optString("remark", "");
        JSONObject u = depth < 2 ? o.optJSONObject("udpNode") : null;
        if (u != null) n.udpNode = fromJson(u, depth + 1);
        n.udpViaInject = o.optBoolean("udpViaInject", true);
        n.udpSrcProfile = o.optString("udpSrcProfile", "");
        n.udpSrcIndex = o.optInt("udpSrcIndex", -1);
        n.udpSrcFp = o.optString("udpSrcFp", "");
        return n;
    }
}
