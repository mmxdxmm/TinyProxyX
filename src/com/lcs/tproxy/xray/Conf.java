package com.lcs.tproxy.xray;

import com.lcs.tproxy.inject.Boot;
import com.lcs.tproxy.inject.HttpDns;
import com.lcs.tproxy.inject.Ini;
import com.lcs.tproxy.model.Kinds;
import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Rule;
import com.lcs.tproxy.model.Store;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Builds a strict xray-core config from a profile. Every emitted key must be a real xray field:
 *  xray rejects unknown keys, so nothing speculative goes in here.
 *
 *  <p>所有「协议 → 出站」「传输 → streamSettings」「TLS 形态 → tls/reality」
 *  「规则字段 → JSON 键」的分派都改成数组下标。构建一份配置只走一遍表，
 *  不再按字符串逐项比较。 */
public class Conf {

    public static final String TAG_PROXY = "proxy";
    public static final String TAG_DIRECT = "direct";
    public static final String TAG_BLOCK = "block";
    /** 注入节点单独挑出来的 UDP 承载出站 */
    public static final String TAG_UDP = "udp-out";
    public static final String TAG_DNS = "dns-out";
    public static final String DNS_TAG = "dns-query";
    /** 解析器域名证书不认 IP 时走这条：先按 hosts 里的 IP 落地，再交给 proxy 出站，
     *  TLS 的 SNI 仍然是域名 —— 定死 IP，但仍然走隧道。 */
    public static final String TAG_DNS_PIN = "dns-pin";
    public static final String IN_SOCKS = "socks-in";
    public static final String IN_HTTP = "http-in";
    public static final String IN_TPROXY = "tproxy-in";
    public static final String IN_REDIRECT = "redirect-in";

    private static final String[] LEVEL = {"debug", "info", "warning", "error"};

    /* ------------------------------------------------------------ dispatch tables */

    private interface OutFn {
        JSONObject make(String tag, Node n) throws Exception;
    }

    private interface NetFn {
        /** @return true when the node is a legacy QUIC hop migrated to XHTTP/H3 */
        boolean apply(JSONObject ss, Node n) throws Exception;
    }

    private interface SecFn {
        void apply(JSONObject ss, Node n, boolean legacyQuic) throws Exception;
    }

    private interface RuleFn {
        void apply(JSONObject o, JSONArray vals) throws Exception;
    }

    private interface WarnFn {
        String check(Profile p);
    }

    private static final OutFn[] OUT = new OutFn[Kinds.TYPE_N];
    private static final NetFn[] NET = new NetFn[Kinds.NET_N];
    private static final SecFn[] SEC = new SecFn[Kinds.SEC_N];
    private static final RuleFn[] RULE = new RuleFn[Kinds.F_N];
    private static final WarnFn[] WARN = new WarnFn[3];
    private static final String[] POLICY_TAG = {TAG_BLOCK, TAG_PROXY, TAG_DIRECT, TAG_PROXY};

    static {
        OUT[Kinds.VLESS] = Conf::vnext;
        OUT[Kinds.VMESS] = Conf::vnext;
        OUT[Kinds.TROJAN] = Conf::serverPass;
        OUT[Kinds.SS] = Conf::shadow;
        OUT[Kinds.SOCKS] = Conf::serverUser;
        OUT[Kinds.HTTP] = Conf::serverUser;
        OUT[Kinds.INJECT] = (t, n) -> {
            throw new IllegalArgumentException("不支持的协议: " + n.type);
        };
        OUT[Kinds.UNKNOWN] = (t, n) -> {
            throw new IllegalArgumentException("不支持的协议: " + n.type);
        };

        NET[Kinds.NET_TCP] = (ss, n) -> false;
        NET[Kinds.NET_WS] = Conf::ws;
        NET[Kinds.NET_GRPC] = Conf::grpc;
        NET[Kinds.NET_H2] = Conf::streamOne;
        NET[Kinds.NET_HTTP] = Conf::streamOne;
        NET[Kinds.NET_QUIC] = Conf::streamOne;
        NET[Kinds.NET_HTTPUPGRADE] = Conf::httpUpgrade;
        NET[Kinds.NET_XHTTP] = Conf::xhttp;
        NET[Kinds.NET_KCP] = Conf::kcp;
        NET[Kinds.NET_UNKNOWN] = (ss, n) -> false;

        SEC[Kinds.SEC_NONE] = (ss, n, q) -> ss.put("security", "none");
        SEC[Kinds.SEC_TLS] = Conf::tls;
        SEC[Kinds.SEC_REALITY] = Conf::reality;
        SEC[Kinds.SEC_UNKNOWN] = (ss, n, q) -> ss.put("security", "none");

        RULE[Kinds.F_DOMAIN] = (o, v) -> o.put("domain", prefixed(v, "full:"));
        RULE[Kinds.F_DOMAIN_SUFFIX] = (o, v) -> o.put("domain", prefixed(v, "domain:"));
        RULE[Kinds.F_DOMAIN_KEYWORD] = (o, v) -> o.put("domain", prefixed(v, "keyword:"));
        RULE[Kinds.F_DOMAIN_REGEX] = (o, v) -> o.put("domain", prefixed(v, "regexp:"));
        RULE[Kinds.F_GEOSITE] = (o, v) -> o.put("domain", prefixed(v, "geosite:"));
        RULE[Kinds.F_IP] = (o, v) -> o.put("ip", v);
        RULE[Kinds.F_GEOIP] = (o, v) -> o.put("ip", prefixed(v, "geoip:"));
        RULE[Kinds.F_PORT] = (o, v) -> o.put("port", join(v));
        RULE[Kinds.F_PROCESS] = (o, v) -> o.put("process", v);
        RULE[Kinds.F_INBOUND] = (o, v) -> o.put("inboundTag", v);
        RULE[Kinds.F_NETWORK] = (o, v) -> o.put("network", join(v));
        RULE[Kinds.F_UNKNOWN] = (o, v) -> o.put("domain", prefixed(v, "domain:"));

        WARN[0] = Conf::warnInject;
        WARN[1] = Conf::warnPlaintext;
        WARN[2] = Conf::warnUdp;
    }

    /**
     * @param injectPort local port of the in-process injector, 0 when the chain has no inject hop
     */
    public static JSONObject build(Profile p, Store.Settings s, boolean root,
                                   int injectPort) throws Exception {
        directDns.clear();
        if (p.rawJson != null && p.rawJson.length() > 0) {
            return rawBuild(p, s, root);
        }
        JSONObject c = new JSONObject();
        c.put("log", new JSONObject().put("loglevel", level(p.logLevel)));

        c.put("inbounds", inbounds(s, root, p.captureV6(), p.sniff));

        /* 53 劫持默认开着（设置里「劫持 53 端口」可以关）：VPN 模式下连着热点的设备
         * 发 DNS 走的是隧道那条路，关掉劫持就等于把 UDP 53 原样丢给节点。节点多数不带
         * UDP，表现就是「热点侧网页加载很慢 / 直接解析不到，本机 IP 检测却正常」。
         * 开着劫持，53 由 xray 自己答，不再依赖节点承载 UDP。 */
        boolean dnsProxy = Profile.DNS_PROXY.equals(p.effectiveDnsPolicy());
        /* 先算 DNS：解析器域名要在这里钉成 IP；钉不了（证书不认那个 IP）时，
         * 路由和出站都得跟着长出一条直连通道，所以顺序不能反。 */
        JSONObject dns = dns(p, s, dnsProxy);
        Out out = outbounds(p, injectPort, dnsProxy);
        c.put("outbounds", out.array);

        c.put("routing", routing(p, s));

        if (dns == null && Profile.DNS_BLOCK.equals(p.effectiveDnsPolicy())) {
            /* Fail closed: a refused local server prevents xray's outbound resolver
             * from silently falling back to the carrier/system DNS. */
            dns = new JSONObject();
            JSONObject dead = new JSONObject();
            dead.put("address", "127.0.0.1");
            dead.put("port", 1);
            dns.put("servers", new JSONArray().put(dead));
            dns.put("tag", DNS_TAG);
        }
        if (dns != null) c.put("dns", dns);
        return c;
    }

    /** Keep the imported JSON's outbounds/routing/dns, replace only local inbounds. */
    private static JSONObject rawBuild(Profile p, Store.Settings s, boolean root) throws Exception {
        JSONObject c = new JSONObject(p.rawJson);
        c.put("log", new JSONObject().put("loglevel", level(p.logLevel)));
        c.put("inbounds", inbounds(s, root, p.captureV6(), p.sniff));
        JSONArray outs = c.optJSONArray("outbounds");
        if (root && outs != null) {
            for (int i = 0; i < outs.length(); i++) {
                JSONObject o = outs.optJSONObject(i);
                if (o != null) mark(o);
            }
        }
        sanitizeRawGeo(c);
        return c;
    }

    /** Imported configs often reference external geo files that are not in the APK
     *  (`ext:geosite.dat:cn`, `ext:geoip-only-cn-private.dat:cn`). Xray has no `ext:`
     *  prefix any more, so those entries used to be dropped outright — which silently
     *  turned a "cn 直连" rule into an empty rule, and an empty rule makes xray refuse
     *  to start ("this rule has no effective fields"). Map them onto the bundled
     *  geosite/geoip tags instead, and drop rules that really have nothing left. */
    private static void sanitizeRawGeo(JSONObject c) throws Exception {
        JSONObject routing = c.optJSONObject("routing");
        JSONArray rules = routing == null ? null : routing.optJSONArray("rules");
        if (rules == null) return;
        JSONArray kept = new JSONArray();
        for (int i = 0; i < rules.length(); i++) {
            JSONObject r = rules.optJSONObject(i);
            if (r == null) continue;
            mapExt(r, "ip", "geoip:");
            mapExt(r, "domain", "geosite:");
            if (hasMatcher(r)) kept.put(r);
        }
        routing.put("rules", kept);
    }

    private static void mapExt(JSONObject r, String key, String prefix) throws Exception {
        JSONArray src = r.optJSONArray(key);
        if (src == null) return;
        JSONArray k = new JSONArray();
        for (int j = 0; j < src.length(); j++) {
            String v = src.optString(j, "");
            String tag = extTag(v);
            if (tag != null) k.put(prefix + tag);
            else if (v.length() > 0) k.put(v);
        }
        if (k.length() > 0) r.put(key, k);
        else r.remove(key);
    }

    /** `ext:geosite.dat:cn` → `cn`；不是 ext: 形式返回 null。 */
    private static String extTag(String v) {
        if (v == null || !v.startsWith("ext:")) return null;
        int c = v.lastIndexOf(':');
        if (c <= 4 || c + 1 >= v.length()) return null;
        String tag = v.substring(c + 1).trim();
        return tag.length() == 0 ? null : tag;
    }

    private static final String[] MATCHER = {"domain", "ip", "port", "sourcePort", "localPort",
            "network", "sourceIP", "user", "inboundTag", "protocol", "attrs", "process", "webhook"};

    /** 规则还剩不剩有效字段；没有的话 xray 会拒绝启动。 */
    private static boolean hasMatcher(JSONObject r) {
        for (String k : MATCHER) if (r.has(k)) return true;
        return false;
    }

    /** 一个层级只做一次查表，不再串四个 equals。 */
    private static String level(String l) {
        for (int i = 0; i < LEVEL.length; i++) if (LEVEL[i].equals(l)) return LEVEL[i];
        return LEVEL[2];
    }

    private static JSONArray inbounds(Store.Settings s, boolean root, boolean captureV6, boolean sniff)
            throws Exception {
        JSONArray a = new JSONArray();
        String listen = s.allowLan ? "0.0.0.0" : "127.0.0.1";
        a.put(socksIn(listen, s.socksPort, sniff));
        a.put(httpIn(listen, s.httpPort, sniff));
        if (root) {
            a.put(tproxyIn(s.tproxyPort, captureV6, sniff));
            a.put(redirectIn(s.redirectPort, captureV6, sniff));
        }
        return a;
    }

    private static JSONObject socksIn(String listen, int port, boolean sniff) throws Exception {
        JSONObject socks = new JSONObject();
        socks.put("tag", IN_SOCKS);
        socks.put("listen", listen);
        socks.put("port", port);
        socks.put("protocol", "socks");
        socks.put("settings", new JSONObject().put("auth", "noauth").put("udp", true).put("userLevel", 0));
        if (sniff) socks.put("sniffing", sniffing());
        return socks;
    }

    private static JSONObject httpIn(String listen, int port, boolean sniff) throws Exception {
        JSONObject http = new JSONObject();
        http.put("tag", IN_HTTP);
        http.put("listen", listen);
        http.put("port", port);
        http.put("protocol", "http");
        http.put("settings", new JSONObject().put("userLevel", 0));
        if (sniff) http.put("sniffing", sniffing());
        return http;
    }

    private static JSONObject tproxyIn(int port, boolean captureV6, boolean sniff) throws Exception {
        JSONObject tp = new JSONObject();
        tp.put("tag", IN_TPROXY);
        /* 绑 "::" 才是双栈：ip6tables 的 TPROXY 目标必须有 v6 套接字接住，
         * 否则 v6 包被 mark 后没人监听，表现是热点下 IPv6 直接不通/漏。 */
        tp.put("listen", captureV6 ? "::" : "0.0.0.0");
        tp.put("port", port);
        tp.put("protocol", "dokodemo-door");
        tp.put("settings", new JSONObject().put("network", "tcp,udp").put("followRedirect", true));
        tp.put("streamSettings", new JSONObject().put("sockopt",
                new JSONObject().put("tproxy", "tproxy")));
        return tp;
    }

    private static JSONObject redirectIn(int port, boolean captureV6, boolean sniff) throws Exception {
        JSONObject rd = new JSONObject();
        rd.put("tag", IN_REDIRECT);
        /* REDIRECT 改的是目的地址：nat OUTPUT 里改成「出口网卡的主地址」，nat PREROUTING 里
         * 改成「入网卡的主地址」。两种情况都不是 127.0.0.1，只绑回环就一个包也收不到 ——
         * 1.4.9 的 root-redirect 模式就是这么整死网络的。这里跟着 tproxy 入站一起绑全地址。 */
        rd.put("listen", captureV6 ? "::" : "0.0.0.0");
        rd.put("port", port);
        rd.put("protocol", "dokodemo-door");
        rd.put("settings", new JSONObject().put("network", "tcp").put("followRedirect", true));
        if (sniff) rd.put("sniffing", sniffing());
        return rd;
    }

    private static JSONObject sniffing() throws Exception {
        return new JSONObject().put("enabled", true)
                .put("destOverride", new JSONArray().put("http").put("tls").put("quic"))
                .put("routeOnly", false);
    }

    private static class Out {
        JSONArray array = new JSONArray();
        boolean hasDnsOut = false;
    }

    /** 一个流量元素：普通节点，或进程内注入器（node == null）。 */
    private static class Hop {
        final Node node;
        final String tag;
        final int injectPort;

        Hop(Node node, String tag, int injectPort) {
            this.node = node;
            this.tag = tag;
            this.injectPort = injectPort;
        }

        JSONObject emit() throws Exception {
            return node == null ? proxyOutbound(tag, "127.0.0.1", injectPort) : nodeOutbound(tag, node);
        }
    }

    /** Number of leading hops served by one local listener.
     *  注入节点在进程内起一个 HTTP 代理，只能占链路第 1 跳。 */
    public static int leadCount(Profile p) {
        return p.chain.size() > 0 && p.chain.get(0).localHop() ? 1 : 0;
    }

    /** true when that leading listener is the in-process HTTP injector. */
    public static boolean leadIsInject(Profile p) {
        return p.chain.size() > 0 && p.chain.get(0).kind() == Kinds.INJECT;
    }

    /** null when the chain can be expressed in one xray config. */
    public static String chainError(Profile p) {
        if (p.chain.isEmpty()) return "链路为空";
        int lead = leadCount(p);
        for (int i = lead; i < p.chain.size(); i++) {
            if (p.chain.get(i).localHop())
                return "注入节点只能放在链路最前面，第 " + (i + 1)
                        + " 跳需要本地监听，xray 拨不回本机";
        }
        /* 空地址的跳一定跑不通：早些时候不管这个，构建出来的配置能起来，
         * 然后每一条连接都对着空地址拨号，日志里全是失败。 */
        for (int i = 0; i < p.chain.size(); i++) {
            Node n = p.chain.get(i);
            if (n.kind() == Kinds.INJECT) continue;  // 地址在 ini 里
            if (n.host == null || n.host.trim().length() == 0)
                return "第 " + (i + 1) + " 跳还没有填地址";
        }
        return null;
    }

    /** 能起来、但这一跳实际没起作用（比如注入节点没填网关）。启动时写一行日志。 */
    public static String chainWarning(Profile p) {
        for (WarnFn w : WARN) {
            String s = w.check(p);
            if (s != null) return s;
        }
        return null;
    }

    private static String warnInject(Profile p) {
        for (int i = 0; i < p.chain.size(); i++) {
            Node n = p.chain.get(i);
            if (n.kind() != Kinds.INJECT) continue;
            Ini c = Ini.parse(n.ini);
            if (c.httpsIp.trim().length() == 0 && c.httpIp.trim().length() == 0) {
                return "第 " + (i + 1) + " 跳是注入节点，但 https_ip / http_ip 都没填："
                        + "它只会把连接原样转发（等于没有这一跳）。"
                        + "要一个能跑的样板，去编辑页点「填入示例」";
            }
            /* 只配 https 的配置很常见（免流网关多数只开 443）。80 端口这时交给 https 槽接管，
             * 和原版一致；但两边的 _direct 都没开时，没有网关的那一侧仍然会直连——会跑真实流量。 */
            if (c.httpIp.trim().length() == 0 && c.httpsIp.trim().length() > 0) {
                return "第 " + (i + 1) + " 跳只配了 https_ip：80 端口的明文 HTTP 会交给 https 槽接管"
                        + "（走 CONNECT 隧道，和原版一致），http_first 不会被注入。";
            }
        }
        return null;
    }

    private static String warnPlaintext(Profile p) {
        /* Xray 26 对「明文 VLESS / Trojan」收紧了：公网地址必须在配置校验阶段就带
         * TLS/REALITY，否则进程起不来。这里提前把话说清楚，别让用户对着
         * "failed to build outbound config" 猜。 */
        for (int i = 0; i < p.chain.size(); i++) {
            Node n = p.chain.get(i);
            if (n.localHop()) continue;
            if (n.kind() != Kinds.VLESS && n.kind() != Kinds.TROJAN) continue;
            if (n.secId() != Kinds.SEC_NONE) continue;
            if (Node.isPrivateHost(n.host)) continue;
            return "第 " + (i + 1) + " 跳是明文 " + n.type.toUpperCase()
                    + "：Xray 26 只允许明文连内网地址，公网明文会拒绝启动。"
                    + "请把 security 改成 tls / reality，或改用 VMess / SS";
        }
        return null;
    }

    private static String warnUdp(Profile p) {
        Node udp = p.udpSplit();
        if (udp == null) return null;
        if (!Profile.UDP_PROXY.equals(p.effectiveUdpPolicy())) {
            return "UDP 转换已选节点，但路由里 UDP 策略不是「代理」，UDP 仍会按 "
                    + p.effectiveUdpPolicy() + " 处理；在注入编辑页点「把 UDP 设为代理」";
        }
        if (!Profile.UDP_PROXY.equals(p.effectiveQuicPolicy())) {
            return "UDP 转换已选节点，但 QUIC（UDP 443）策略是 "
                    + p.effectiveQuicPolicy() + "，QUIC 流量不会走这个节点";
        }
        if (p.udpSplitViaInject() && !Node.udpOverTcp(udp)) {
            return "UDP 承载节点（" + udp.type.toUpperCase() + "）的 UDP 不走 TCP 隧道，"
                    + "无法经注入网关；启动时会改为直连该节点";
        }
        if (p.udpSplitViaInject() && (udp.netId() == Kinds.NET_KCP || udp.netId() == Kinds.NET_QUIC)) {
            return "UDP 承载节点用的是 " + udp.net + " 传输，无法经注入网关拨号；"
                    + "请改成「直连该节点」或换一个 TCP 传输的节点";
        }
        return null;
    }

    private static Out outbounds(Profile p, int injectPort, boolean hijack) throws Exception {
        Out out = new Out();
        List<Node> chain = p.chain;
        int lead = leadCount(p);
        boolean hasInject = lead > 0 && injectPort > 0;

        List<Hop> hops = new ArrayList<Hop>();
        if (hasInject) hops.add(new Hop(null, "hopg", injectPort));
        for (int i = lead; i < chain.size(); i++) {
            hops.add(new Hop(chain.get(i), "hop" + hops.size(), injectPort));
        }
        if (hops.isEmpty()) throw new Exception("链路无法构建");

        int exitIdx = hops.size() - 1;
        for (int i = exitIdx; i >= 0; i--) {
            String tag = i == exitIdx ? TAG_PROXY : hops.get(i).tag;
            JSONObject o = hops.get(i).emit();
            o.put("tag", tag);
            /* 出站 i 经出站 i-1 才能到它的服务器；xray 25+ 放在
             * streamSettings.sockopt.dialerProxy，不再用 outbound.proxySettings。 */
            if (i > 0) dialer(o, hops.get(i - 1).tag);
            if (i == exitIdx) o.put("mux", new JSONObject().put("enabled", p.mux).put("concurrency", 8));
            mark(o);
            out.array.put(o);
        }

        /* UDP 转换：注入链路只能走 TCP，UDP 需要一个真正的 UDP 出站。
         * viaInject=true 时让这个出站的服务器连接先经注入网关（dialerProxy=proxy），
         * 免流仍然生效；false 时直连它，省掉注入网关那一跳的延迟。 */
        Node udp = p.udpSplit();
        /* 只有「代理」这一档真的会被路由指到 udp-out 时才发这个出站：
         * 用户在路由里把 UDP 设成 block/direct 时，多一个没人用的出站只会让配置难读，
         * 也会让「选了节点但其实没生效」看起来像生效了。 */
        boolean udpUsed = Profile.UDP_PROXY.equals(p.effectiveUdpPolicy())
                || Profile.UDP_PROXY.equals(p.effectiveQuicPolicy());
        if (udp != null && udpUsed) {
            JSONObject o = nodeOutbound(TAG_UDP, udp);
            boolean viaInject = p.udpSplitViaInject() && hasInject && Node.udpOverTcp(udp)
                    && udp.netId() != Kinds.NET_KCP && udp.netId() != Kinds.NET_QUIC;
            if (viaInject) dialer(o, TAG_PROXY);
            mark(o);
            out.array.put(o);
        }

        JSONObject direct = freedom(TAG_DIRECT);
        mark(direct);
        out.array.put(direct);
        out.array.put(blackhole(TAG_BLOCK));
        if (hijack) {
            JSONObject dnsOut = new JSONObject();
            dnsOut.put("tag", TAG_DNS);
            dnsOut.put("protocol", "dns");
            dnsOut.put("settings", new JSONObject());
            out.array.put(dnsOut);
            out.hasDnsOut = true;
        }
        if (!directDns.isEmpty()) {
            JSONObject d = freedom(TAG_DNS_PIN);
            mark(d);
            /* 先用 hosts 里启动时钉死的 IP 把域名解掉（domainStrategy=UseIP），再把这条
             * 已经带 IP 的连接交给 proxy 出站（dialerProxy）—— 节点收到的是 IP，不再自己解析；
             * DoH 的 TLS 在这一层之上，SNI 还是域名，证书照常校验。 */
            d.put("settings", new JSONObject().put("domainStrategy", "UseIP"));
            if (hijack) dialer(d, TAG_PROXY);
            out.array.put(d);
        }
        return out;
    }

    private static JSONObject freedom(String tag) throws Exception {
        JSONObject o = new JSONObject();
        o.put("tag", tag);
        o.put("protocol", "freedom");
        o.put("settings", new JSONObject());
        return o;
    }

    private static JSONObject blackhole(String tag) throws Exception {
        JSONObject o = new JSONObject();
        o.put("tag", tag);
        o.put("protocol", "blackhole");
        o.put("settings", new JSONObject());
        return o;
    }

    /** 把 outbound 的服务器连接挂到上一条出站上。 */
    private static void dialer(JSONObject o, String tag) throws Exception {
        JSONObject ss = o.optJSONObject("streamSettings");
        if (ss == null) ss = new JSONObject();
        JSONObject sockopt = ss.optJSONObject("sockopt");
        if (sockopt == null) sockopt = new JSONObject();
        sockopt.put("dialerProxy", tag);
        ss.put("sockopt", sockopt);
        o.put("streamSettings", ss);
    }

    /** Keep xray's own sockets out of the root capture chains.
     *  不再写 sockopt.mark：Android 用 fwmark 选网络，自己盖一个 255 会让内核落到
     *  `ip rule … unreachable`，root 模式下 xray 拨节点直接 connect: network is unreachable。
     *  root 模式 xray 是 uid 0，Root 的 --uid-owner 0 已经豁免了。 */
    private static void mark(JSONObject o) throws Exception {
        JSONObject ss = o.optJSONObject("streamSettings");
        if (ss == null) ss = new JSONObject();
        JSONObject sockopt = ss.optJSONObject("sockopt");
        if (sockopt == null) sockopt = new JSONObject();
        ss.put("sockopt", sockopt);
        o.put("streamSettings", ss);
    }

    private static JSONObject nodeOutbound(String tag, Node n) throws Exception {
        JSONObject o = OUT[n.kind()].make(tag, n);
        o.put("tag", tag);
        JSONObject ss = stream(n);
        if (ss.length() > 0) o.put("streamSettings", ss);
        return o;
    }

    /* ---------------------------------------------------------------- outbounds */

    private static JSONObject vnext(String tag, Node n) throws Exception {
        JSONObject o = new JSONObject();
        o.put("protocol", n.type);
        JSONObject user = new JSONObject();
        user.put("id", n.uuid);
        user.put("level", 0);
        if (n.kind() == Kinds.VLESS) {
            user.put("encryption", "none");
            if (n.flow != null && n.flow.length() > 0) user.put("flow", n.flow);
        } else {
            user.put("alterId", n.alterId);
            user.put("security", n.vmessScy == null || n.vmessScy.length() == 0 ? "auto" : n.vmessScy);
        }
        JSONObject vn = new JSONObject();
        vn.put("address", n.host);
        vn.put("port", n.port);
        vn.put("users", new JSONArray().put(user));
        o.put("settings", new JSONObject().put("vnext", new JSONArray().put(vn)));
        return o;
    }

    private static JSONObject serverPass(String tag, Node n) throws Exception {
        JSONObject o = new JSONObject();
        o.put("protocol", "trojan");
        JSONObject srv = new JSONObject();
        srv.put("address", n.host);
        srv.put("port", n.port);
        srv.put("password", n.password);
        srv.put("level", 0);
        if (n.uot) srv.put("uot", true);
        o.put("settings", new JSONObject().put("servers", new JSONArray().put(srv)));
        return o;
    }

    private static JSONObject shadow(String tag, Node n) throws Exception {
        JSONObject o = new JSONObject();
        o.put("protocol", "shadowsocks");
        JSONObject srv = new JSONObject();
        srv.put("address", n.host);
        srv.put("port", n.port);
        srv.put("method", n.method);
        srv.put("password", n.password);
        srv.put("level", 0);
        if (n.uot) srv.put("uot", true);
        o.put("settings", new JSONObject().put("servers", new JSONArray().put(srv)));
        return o;
    }

    private static JSONObject serverUser(String tag, Node n) throws Exception {
        JSONObject srv = new JSONObject();
        srv.put("address", n.host);
        srv.put("port", n.port);
        if (n.user != null && n.user.length() > 0) {
            JSONObject u = new JSONObject();
            u.put("user", n.user);
            u.put("pass", n.password);
            u.put("level", 0);
            srv.put("users", new JSONArray().put(u));
        }
        JSONObject o = new JSONObject();
        o.put("protocol", n.type);
        o.put("settings", new JSONObject().put("servers", new JSONArray().put(srv)));
        return o;
    }

    /** xray http outbound: how traffic reaches the in-process inject proxy. */
    private static JSONObject proxyOutbound(String tag, String host, int port) throws Exception {
        JSONObject o = new JSONObject();
        o.put("tag", tag);
        o.put("protocol", "http");
        JSONObject srv = new JSONObject();
        srv.put("address", host);
        srv.put("port", port);
        o.put("settings", new JSONObject().put("servers", new JSONArray().put(srv)));
        return o;
    }

    /* ------------------------------------------------------------ stream settings */

    /** streamSettings for a hop; empty object when everything is plain tcp. */
    public static JSONObject stream(Node n) throws Exception {
        JSONObject ss = new JSONObject();
        String net = n.net == null || n.net.isEmpty() ? "tcp" : n.net;
        ss.put("network", net);
        boolean legacyQuic = NET[n.netId()].apply(ss, n);
        SEC[n.secId()].apply(ss, n, legacyQuic);
        return ss;
    }

    private static boolean ws(JSONObject ss, Node n) throws Exception {
        JSONObject ws = new JSONObject();
        ws.put("path", empty(n.path) ? "/" : n.path);
        /* xray 26 起 wsSettings.host 是独立字段；旧的 headers.Host 会报
         * "deprecated, being migrated to independent host"。 */
        if (!empty(n.hostHdr)) ws.put("host", n.hostHdr);
        ss.put("wsSettings", ws);
        return false;
    }

    private static boolean grpc(JSONObject ss, Node n) throws Exception {
        JSONObject g = new JSONObject().put("serviceName", n.serviceName == null ? "" : n.serviceName);
        /* v2rayNG 把 gRPC 的 request host 映射到 authority */
        if (!empty(n.hostHdr)) g.put("authority", n.hostHdr);
        ss.put("grpcSettings", g);
        return false;
    }

    /** h2 / http / quic 在 Xray 26 已整条移除，官方迁移路径是 XHTTP stream-one
     *  （h2 → H2，quic → H3）。老节点不逼用户手改，这里直接按迁移路径发出去；
     *  导出的链接仍保留原始 net。 */
    private static boolean streamOne(JSONObject ss, Node n) throws Exception {
        JSONObject h = new JSONObject();
        h.put("path", empty(n.path) ? "/" : n.path);
        if (!empty(n.hostHdr)) h.put("host", n.hostHdr);
        h.put("mode", "stream-one");
        ss.put("network", "xhttp");
        ss.put("xhttpSettings", h);
        return n.netId() == Kinds.NET_QUIC;      /* 老 quic 补 alpn h3 */
    }

    private static boolean httpUpgrade(JSONObject ss, Node n) throws Exception {
        JSONObject h = new JSONObject();
        h.put("path", empty(n.path) ? "/" : n.path);
        if (!empty(n.hostHdr)) h.put("host", n.hostHdr);
        ss.put("httpupgradeSettings", h);
        return false;
    }

    private static boolean xhttp(JSONObject ss, Node n) throws Exception {
        JSONObject h = new JSONObject();
        h.put("path", empty(n.path) ? "/" : n.path);
        if (!empty(n.hostHdr)) h.put("host", n.hostHdr);
        h.put("mode", "auto");
        ss.put("xhttpSettings", h);
        return false;
    }

    private static boolean kcp(JSONObject ss, Node n) throws Exception {
        ss.put("kcpSettings", new JSONObject().put("header",
                new JSONObject().put("type", empty(n.headerType) ? "none" : n.headerType)));
        return false;
    }

    private static void tls(JSONObject ss, Node n, boolean legacyQuic) throws Exception {
        JSONObject t = new JSONObject();
        t.put("serverName", empty(n.sni) ? n.host : n.sni);
        t.put("allowInsecure", n.allowInsecure);
        JSONArray al = alpn(n.alpn);
        if (al.length() > 0) t.put("alpn", al);
        else if (legacyQuic) t.put("alpn", new JSONArray().put("h3"));
        if (!empty(n.fp)) t.put("fingerprint", n.fp);
        ss.put("security", "tls");
        ss.put("tlsSettings", t);
    }

    private static JSONArray alpn(String v) {
        JSONArray al = new JSONArray();
        if (v == null) return al;
        for (String x : v.split("[,|]")) if (x.trim().length() > 0) al.put(x.trim());
        return al;
    }

    private static void reality(JSONObject ss, Node n, boolean legacyQuic) throws Exception {
        JSONObject r = new JSONObject();
        r.put("serverName", empty(n.sni) ? n.host : n.sni);
        r.put("fingerprint", empty(n.fp) ? "chrome" : n.fp);
        r.put("publicKey", n.pbk);
        r.put("shortId", n.sid == null ? "" : n.sid);
        r.put("spiderX", empty(n.spx) ? "/" : n.spx);
        ss.put("security", "reality");
        ss.put("realitySettings", r);
    }

    private static boolean empty(String s) {
        return s == null || s.length() == 0;
    }

    private static String outbound(String policy) {
        return POLICY_TAG[Kinds.policy(policy, Kinds.POL_PROXY)];
    }

    private static JSONObject routing(Profile p, Store.Settings s) throws Exception {
        JSONObject r = new JSONObject();
        r.put("domainStrategy", "IPIfNonMatch");
        JSONArray rules = new JSONArray();
        String dns = p.effectiveDnsPolicy();
        String udp = p.effectiveUdpPolicy();
        String quic = p.effectiveQuicPolicy();

        /* DNS 模块的查询如果是「证书不认 IP」的解析器，只给这一条换出站：
         * 连接落到启动时钉死的 IP，SNI 还是域名，而且仍然走隧道。 */
        if (!directDns.isEmpty()) {
            JSONArray hosts = new JSONArray();
            for (String h : directDns) hosts.put("full:" + h);
            rules.put(field("inboundTag", DNS_TAG).put("domain", hosts)
                    .put("outboundTag", TAG_DNS_PIN));
        }

        /* DNS module's own queries are a separate traffic class. */
        rules.put(field("inboundTag", DNS_TAG).put("outboundTag", outbound(dns)));

        /* App DNS: proxy -> built-in resolver; direct/block are explicit choices. */
        rules.put(new JSONObject().put("type", "field").put("port", "53")
                .put("outboundTag", Profile.DNS_PROXY.equals(dns) ? TAG_DNS : outbound(dns)));

        /* IPv6 policy comes after DNS so block does not swallow an explicit DNS choice. */
        if (p.blockV6()) {
            rules.put(field("ip", "::/0").put("outboundTag", TAG_BLOCK));
        }

        /* UDP 转换开着时，「代理」这一档改走 udp-out；用户明确选直连/禁用时仍按原策略，
         * 不把 UDP 偷偷塞进链路。QUIC 443 更具体，必须排在通用 UDP 前面。 */
        boolean split = p.udpSplit() != null;
        String udpTarget = split && Profile.UDP_PROXY.equals(udp) ? TAG_UDP : outbound(udp);
        String quicTarget = split && Profile.UDP_PROXY.equals(quic) ? TAG_UDP : outbound(quic);
        rules.put(new JSONObject().put("type", "field").put("network", "udp")
                .put("port", "443").put("outboundTag", quicTarget));
        rules.put(new JSONObject().put("type", "field").put("network", "udp")
                .put("outboundTag", udpTarget));

        if (Profile.P_BYPASS_LAN.equals(p.preset)) {
            rules.put(field("ip", "geoip:private").put("outboundTag", TAG_DIRECT));
        }
        if (Profile.P_BYPASS_CN.equals(p.preset)) {
            /* 域名规则必须排在 IP 规则前面：DNS 被污染时同一域名会被解析到国内 IP，
             * 先按 IP 判断就会把墙外站点整片判成"国内直连"。 */
            JSONArray site = new JSONArray();
            site.put("geosite:cn");
            if (s.bypassPrivate) site.put("geosite:private");
            rules.put(field("domain", site).put("outboundTag", TAG_DIRECT));
            JSONArray ip = new JSONArray();
            ip.put("geoip:cn");
            if (s.bypassPrivate) ip.put("geoip:private");
            rules.put(field("ip", ip).put("outboundTag", TAG_DIRECT));
        }

        for (Rule u : p.rules) {
            if (u.value == null || u.value.trim().isEmpty()) continue;
            JSONArray vals = splitValues(u.value);
            if (vals.length() == 0) continue;
            JSONObject o = new JSONObject();
            o.put("type", "field");
            RULE[Kinds.field(u.field)].apply(o, vals);
            if (u.invert) o.put("invert", true);
            o.put("outboundTag", Rule.A_DIRECT.equals(u.action) ? TAG_DIRECT
                    : Rule.A_BLOCK.equals(u.action) ? TAG_BLOCK : TAG_PROXY);
            rules.put(o);
        }
        r.put("rules", rules);
        return r;
    }

    /** xray 的匹配字段都是列表；单值也包成一条，别让 string/array 两种形态混着发。 */
    private static JSONObject field(String key, String value) throws Exception {
        return new JSONObject().put("type", "field").put(key, new JSONArray().put(value));
    }

    private static JSONObject field(String key, JSONArray value) throws Exception {
        return new JSONObject().put("type", "field").put(key, value);
    }

    private static JSONArray splitValues(String v) {
        JSONArray vals = new JSONArray();
        for (String x : v.split("[,\\s]+")) if (x.trim().length() > 0) vals.put(x.trim());
        return vals;
    }

    private static JSONArray prefixed(JSONArray vals, String prefix) {
        JSONArray out = new JSONArray();
        for (int i = 0; i < vals.length(); i++) {
            String v = vals.optString(i);
            out.put(v.indexOf(':') >= 0 ? v : prefix + v);
        }
        return out;
    }

    private static String join(JSONArray a) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            if (i > 0) sb.append(",");
            sb.append(a.optString(i));
        }
        return sb.toString();
    }

    /** The resolver pair actually in force, or null when no dns section is emitted at all.
     *  [0] = remote / default resolver, [1] = domestic resolver. */
    private static String[] effectiveDns(Profile p, Store.Settings s, boolean hijack) {
        boolean own = s.dnsEnabled;
        boolean profileDns = p.overrideDns || (p.dnsRemote != null && p.dnsRemote.length() > 0);
        /* 劫持开着就必须给出一组解析器：dns-out 没有 servers 会退回系统解析，
         * 而系统解析在 VPN 里又指回隧道，等于自己问自己。 */
        if (!own && !profileDns && !hijack) return null;
        /* 默认都用阿里的 DoH，而且写 IP：DoH 的域名自己也要解析，
         * 注入模式下那条解析会绕回 xray 的 DNS，直接写 IP 断掉这个环。 */
        String domestic = nz(own ? s.dnsDomestic : p.dnsDirect, "https://223.5.5.5/dns-query");
        String remote = nz(own ? s.dnsRemote : p.dnsRemote, "https://223.5.5.5/dns-query");
        return new String[]{remote, domestic};
    }

    /** Global DNS. Domestic first (only for cn names), remote as the default resolver.
     *  Address forms are exactly what xray 26 accepts: 1.1.1.1 / tcp:// / tls:// / https:// */
    private static JSONObject dns(Profile p, Store.Settings s, boolean hijack) throws Exception {
        String[] res = effectiveDns(p, s, hijack);
        if (res == null) return null;
        /* 解析器域名先钉成 IP。DoH 写域名时"谁来解析这个域名"没有安全答案：走代理是节点去解析
         * （节点 DNS 一歪，整条 DNS 链跟着废），走直连是自己解析自己。钉成 IP 之后这条链
         * 就没有悬念了 —— 注入模式和 xray 模式都是同一条路。 */
        JSONObject hosts = bootHosts(res[0], res[1]);
        String remote = pin(res[0]);
        String domestic = res[1].equals(res[0]) ? remote : pin(res[1]);

        JSONArray servers = new JSONArray();
        if (!domestic.equals(remote)) {
            JSONObject cn = new JSONObject();
            cn.put("address", domestic);
            JSONArray domains = new JSONArray();
            domains.put("geosite:cn");
            domains.put("geosite:private");
            cn.put("domains", domains);
            JSONArray expect = new JSONArray();
            expect.put("geoip:cn");
            cn.put("expectIPs", expect);
            servers.put(cn);
        }
        servers.put(remote);

        JSONObject d = new JSONObject();
        d.put("servers", servers);
        /* UseIPv4 会把 AAAA 全部丢掉（xray 里 option.IPv6Enable 要和 queryStrategy 做与运算），
         * v6-only 的节点/解析器连自己都解析不出来。只有用户明确选了「v6 丢黑洞」才退回
         * UseIPv4 —— 那种策略下把 AAAA 发给应用，应用连不上还要等超时。 */
        d.put("queryStrategy", p.blockV6() ? "UseIPv4" : "UseIP");
        d.put("tag", DNS_TAG);
        /* bootstrap 解析过的名字（节点域名、解析器域名）直接写死：
         * xray 内部再查这些名字时命中 hosts，不碰系统 DNS。 */
        if (hosts.length() > 0) d.put("hosts", hosts);
        return d;
    }

    /** dns.hosts：bootstrap 缓存 + 解析器域名 → IP */
    private static JSONObject bootHosts(String... resolvers) {
        JSONObject h = new JSONObject();
        try {
            for (String r : resolvers) {
                String host = schemeHost(r);
                if (host.length() == 0 || HttpDns.isIp(host)) continue;
                String ip = resolver(host);
                if (ip != null) h.put(host, ip);
            }
            for (Map.Entry<String, String> e : Boot.snapshot().entrySet()) {
                if (e.getKey() != null && e.getValue() != null) h.put(e.getKey(), e.getValue());
            }
        } catch (Exception ignored) {
        }
        return h;
    }

    /** 解析器域名 → 一个 IP（v4 优先）。bootstrap 优先，没开就用系统解析
     *  （app 自己不在 VPN 里，这一步不会绕回隧道）。 */
    private static String resolver(String host) {
        java.util.List<String> all = resolverAll(host);
        return all.isEmpty() ? null : all.get(0);
    }

    /** 候选地址，v4 在前。 */
    private static java.util.List<String> resolverAll(String host) {
        java.util.List<String> v4 = new java.util.ArrayList<String>();
        java.util.List<String> v6 = new java.util.ArrayList<String>();
        String boot = Boot.resolve(host);
        if (boot != null) (boot.indexOf(':') >= 0 ? v6 : v4).add(boot);
        try {
            for (java.net.InetAddress a : java.net.InetAddress.getAllByName(host)) {
                String s = a.getHostAddress();
                if (v4.contains(s) || v6.contains(s)) continue;
                (a instanceof java.net.Inet4Address ? v4 : v6).add(s);
            }
        } catch (Exception ignored) {
        }
        v4.addAll(v6);
        /* 已知域名：把预置的官方 IP 提到最前面，别钉到一条实际走不通的地址上 */
        for (String[] k : KNOWN_RESOLVER) {
            if (!k[0].equalsIgnoreCase(host)) continue;
            int at = v4.indexOf(k[1]);
            if (at > 0) {
                v4.remove(at);
                v4.add(0, k[1]);
            }
            break;
        }
        return v4;
    }

    /** 已知解析器域名 → 官方 IP（和设置页预置的写法一致）。 */
    private static final String[][] KNOWN_RESOLVER = {
            {"dns.alidns.com", "223.5.5.5"},
            {"doh.pub", "1.12.12.12"},
            {"dns.google", "8.8.8.8"},
            {"cloudflare-dns.com", "1.1.1.1"},
    };

    /** https://dns.alidns.com/dns-query → https://223.5.5.5/dns-query。
     *  只钉 https/tls 这两种带证书的形态，而且先用 IP 当 peer host 验一次证书 ——
     *  证书不认这个 IP 就保持域名，改走 dns-pin。 */
    private static String pin(String address) {
        String a = address == null ? "" : address.trim();
        int i = a.indexOf("://");
        if (i <= 0) return a;
        String scheme = a.substring(0, i + 3);
        boolean tls = scheme.equalsIgnoreCase("https://") || scheme.equalsIgnoreCase("tls://");
        if (!tls) return a;
        String host = schemeHost(a);
        if (host.length() == 0 || HttpDns.isIp(host)) return a;
        java.util.List<String> cand = resolverAll(host);
        if (cand.isEmpty()) {
            note("解析器 " + host + " 解析不到 IP，保留域名");
            return a;
        }
        int port = portOf(a, scheme.equalsIgnoreCase("tls://") ? 853 : 443);
        String ip = null;
        for (String c : cand) {
            if (coversIp(c, port)) {
                ip = c;
                break;
            }
        }
        if (ip == null) {
            /* 证书不认这个 IP，写 IP 必挂 TLS。改成「启动时钉死的 IP + 域名 SNI」：
             * hosts 里有 IP，dns-pin 出站先落到 IP 再交给 proxy，隧道照走。 */
            if (!directDns.contains(host)) directDns.add(host);
            note("解析器 " + host + " 的 IP 证书都不认，改用 dns-pin（IP 已钉死，SNI 仍是域名，仍走隧道）");
            return a;
        }
        String rest = a.substring(i + 3);
        int slash = rest.indexOf('/');
        String auth = slash >= 0 ? rest.substring(0, slash) : rest;
        String tail = slash >= 0 ? rest.substring(slash) : "";
        int at = auth.lastIndexOf('@');
        String user = at >= 0 ? auth.substring(0, at + 1) : "";
        String hp = at >= 0 ? auth.substring(at + 1) : auth;
        String portPart = "";
        if (!hp.startsWith("[")) {
            int c = hp.lastIndexOf(':');
            if (c > 0) portPart = hp.substring(c);
        }
        String lit = ip.indexOf(':') >= 0 ? "[" + ip + "]" : ip;
        note("解析器 " + host + " → " + ip + "（已写成 IP）");
        return scheme + user + lit + portPart + tail;
    }

    /** 地址里写的端口；没写就用 def。 */
    private static int portOf(String a, int def) {
        String rest = a.substring(a.indexOf("://") + 3);
        int slash = rest.indexOf('/');
        String auth = slash >= 0 ? rest.substring(0, slash) : rest;
        int at = auth.lastIndexOf('@');
        if (at >= 0) auth = auth.substring(at + 1);
        int c = auth.startsWith("[") ? auth.indexOf(']') + 1 : auth.lastIndexOf(':');
        if (c > 0 && c + 1 < auth.length() && auth.charAt(c) == ':') {
            try {
                return Integer.parseInt(auth.substring(c + 1).trim());
            } catch (Exception ignored) {
            }
        }
        return def;
    }

    /** 用 IP 当 peer host 做一次 TLS，确认证书里有这个 IP（xray 的 DoH 写 IP 时就是这么校验的）。 */
    private static boolean coversIp(String ip, int port) {
        java.net.Socket raw = new java.net.Socket();
        try {
            raw.connect(new java.net.InetSocketAddress(ip, port), 3000);
            raw.setSoTimeout(3000);
            javax.net.ssl.SSLSocket s = (javax.net.ssl.SSLSocket)
                    ((javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault())
                            .createSocket(raw, ip, port, true);
            javax.net.ssl.SSLParameters sp = s.getSSLParameters();
            sp.setEndpointIdentificationAlgorithm("HTTPS");
            s.setSSLParameters(sp);
            s.startHandshake();
            s.close();
            return true;
        } catch (Exception e) {
            try {
                raw.close();
            } catch (Exception ignored) {
            }
            return false;
        }
    }

    /** 证书不认 IP 的解析器域名（走 dns-pin 出站） */
    private static final java.util.List<String> directDns = new java.util.ArrayList<String>();
    private static final java.util.List<String> notes = new java.util.ArrayList<String>();

    private static void note(String n) {
        synchronized (notes) {
            notes.add(n);
        }
    }

    /** 取走构建期间记下的说明，给启动日志用；没有就返回 null。 */
    public static String takeNotes() {
        synchronized (notes) {
            if (notes.isEmpty()) return null;
            StringBuilder b = new StringBuilder();
            for (String n : notes) b.append(b.length() == 0 ? "" : "；").append(n);
            notes.clear();
            return b.toString();
        }
    }

    /** https://dns.alidns.com/dns-query → dns.alidns.com；tls://8.8.8.8 → 8.8.8.8 */
    private static String schemeHost(String address) {
        if (address == null) return "";
        String a = address.trim();
        int i = a.indexOf("://");
        if (i > 0) a = a.substring(i + 3);
        else return "";
        int slash = a.indexOf('/');
        if (slash >= 0) a = a.substring(0, slash);
        int at = a.lastIndexOf('@');
        if (at >= 0) a = a.substring(at + 1);
        if (!a.startsWith("[")) {
            int colon = a.lastIndexOf(':');
            if (colon > 0) a = a.substring(0, colon);
        }
        return a;
    }

    private static String nz(String v, String def) {
        return v == null || v.trim().length() == 0 ? def : v.trim();
    }
}
