package com.lcs.tproxy.inject;

import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Rule;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.xray.Conf;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * 配置差分器：同一批输入喂给 1.8.2 与 2.0.0 的 Conf.build，把结果规范化后逐行输出，
 * 两份输出用 diff 比较。任何字段、任何值不同都会暴露。
 *
 * 输出格式：name<TAB>normalized-json（或 EX:异常类型:消息）
 */
public final class ConfDiff {

    /* ---------------------------------------------------------------- 规范化 */

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String norm(Object o) {
        if (o == null || o == JSONObject.NULL) return "null";
        if (o instanceof JSONObject) {
            JSONObject j = (JSONObject) o;
            List<String> keys = new ArrayList<String>();
            Iterator<String> it = j.keys();
            while (it.hasNext()) keys.add(it.next());
            Collections.sort(keys);
            StringBuilder b = new StringBuilder("{");
            for (int i = 0; i < keys.size(); i++) {
                String k = keys.get(i);
                if (i > 0) b.append(',');
                b.append(quote(k)).append(':').append(norm(j.opt(k)));
            }
            return b.append('}').toString();
        }
        if (o instanceof JSONArray) {
            JSONArray a = (JSONArray) o;
            StringBuilder b = new StringBuilder("[");
            for (int i = 0; i < a.length(); i++) {
                if (i > 0) b.append(',');
                b.append(norm(a.opt(i)));
            }
            return b.append(']').toString();
        }
        if (o instanceof String) return quote((String) o);
        if (o instanceof Boolean) return o.toString();
        if (o instanceof Number) {
            double d = ((Number) o).doubleValue();
            long l = ((Number) o).longValue();
            return d == (double) l ? Long.toString(l) : o.toString();
        }
        return quote(String.valueOf(o));
    }

    /* ---------------------------------------------------------------- 输入构造 */

    private static int n;

    public static void main(String[] args) throws Exception {
        /* 1. 协议 × 传输 × 安全，含非法组合（生成器不该因为 xray 会拒绝就改输出） */
        String[] protocols = {Node.VLESS, Node.VMESS, Node.TROJAN, Node.SS, Node.SOCKS, Node.HTTP,
                Node.INJECT, "unknown-proto"};
        String[] nets = {"tcp", "raw", "ws", "grpc", "h2", "http", "httpupgrade", "xhttp",
                "kcp", "quic", "unknown-net", ""};
        String[] secs = {"none", "tls", "reality", "xtls", ""};

        for (String proto : protocols) {
            for (String net : nets) {
                for (String sec : secs) {
                    Profile p = one(proto, sec);
                    setNet(p, net);
                    write("grid-" + proto + "-" + net + "-" + sec, p, false, 0, new Store.Settings());
                }
            }
        }

        /* 2. root 模式：四种入站的组合 */
        String[] modes = {"vpn", "root"};
        boolean[] lans = {false, true};
        boolean[] v6 = {false, true};
        boolean[] sniff = {false, true};
        for (boolean root : new boolean[]{false, true}) {
            for (String mode : modes) {
                for (boolean lan : lans) {
                    for (boolean ipv6 : v6) {
                        for (boolean sn : sniff) {
                            Profile p = one(Node.VLESS, "tls");
                            p.v6 = ipv6 ? Profile.V6_PROXY : Profile.V6_DIRECT;
                            p.sniff = sn;
                            p.mux = lan;
                            Store.Settings s = new Store.Settings();
                            s.mode = mode;
                            s.allowLan = lan;
                            s.rootHotspot = lan;
                            s.rootProxyLocal = !lan;
                            s.rootUdp = ipv6;
                            s.rootIpv6 = ipv6;
                            write("in-" + root + "-" + mode + "-" + lan + "-" + ipv6 + "-" + sn,
                                    p, root, 0, s);
                        }
                    }
                }
            }
        }

        /* 3. 链式：2/3/4 跳，各协议组合，inject 在头/中/尾 */
        String[] chainProtos = {Node.VLESS, Node.TROJAN, Node.SS, Node.VMESS, Node.SOCKS, Node.HTTP};
        for (String a : chainProtos) {
            for (String b : chainProtos) {
                Profile p = new Profile("c2");
                p.chain.add(mk(a, "a.example.com", 443, "tls"));
                p.chain.add(mk(b, "b.example.com", 8443, "reality"));
                write("chain2-" + a + "-" + b, p, false, 0, new Store.Settings());
            }
        }
        for (String mid : new String[]{Node.VLESS, Node.INJECT, Node.SOCKS}) {
            Profile p = new Profile("c3");
            p.chain.add(mk(Node.VMESS, "a.example.com", 443, "tls"));
            Node m = mid.equals(Node.INJECT) ? inject("https_ip=192.168.1.1;") : mk(mid, "m.example.com", 80, "none");
            p.chain.add(m);
            p.chain.add(mk(Node.TROJAN, "c.example.com", 443, "reality"));
            write("chain3-mid-" + mid, p, false, 45871, new Store.Settings());
            write("chain3-mid-root-" + mid, p, true, 45871, new Store.Settings());
        }
        Profile c4 = new Profile("c4");
        c4.chain.add(mk(Node.VLESS, "a.example.com", 443, "tls"));
        c4.chain.add(mk(Node.VMESS, "b.example.com", 443, "ws"));
        c4.chain.add(mk(Node.TROJAN, "c.example.com", 443, "grpc"));
        c4.chain.add(mk(Node.SS, "d.example.com", 443, "tls"));
        write("chain4", c4, false, 0, new Store.Settings());

        /* 4. inject 单跳 / inject + UDP 承载的九种组合 */
        String[] udpNets = {"tcp", "ws", "grpc", "kcp", "quic", "httpupgrade", "xhttp"};
        String[] udpSecs = {"tls", "reality", "none"};
        for (String net : udpNets) {
            for (String sec : udpSecs) {
                for (int via = 0; via < 2; via++) {
                    for (int uot = 0; uot < 2; uot++) {
                        Profile p = new Profile("udp");
                        Node h = inject("https_ip=192.168.1.1;\nhttps_port=443;");
                        h.udpNode = mk(Node.VLESS, "u.example.com", 443, sec);
                        h.udpNode.net = net;
                        h.udpNode.uot = uot == 1;
                        h.udpViaInject = via == 1;
                        p.chain.add(h);
                        p.udpPolicy = Profile.UDP_PROXY;
                        p.quicPolicy = via == 1 ? Profile.UDP_PROXY : Profile.UDP_BLOCK;
                        write("udp-" + net + "-" + sec + "-via" + via + "-uot" + uot,
                                p, false, 45873, new Store.Settings());
                    }
                }
            }
        }

        /* 5. UDP 三态 × QUIC 三态 × 有无注入节点 */
        String[] tri = {Profile.UDP_PROXY, Profile.UDP_DIRECT, Profile.UDP_BLOCK, "bogus"};
        for (String u : tri) {
            for (String q : tri) {
                for (int inj = 0; inj < 2; inj++) {
                    Profile p = new Profile("pol");
                    if (inj == 1) p.chain.add(inject("https_ip=10.0.0.1;"));
                    p.chain.add(mk(Node.VLESS, "n.example.com", 443, "tls"));
                    p.udpPolicy = u;
                    p.quicPolicy = q;
                    write("pol-" + u + "-" + q + "-" + inj, p, false, inj == 1 ? 45874 : 0,
                            new Store.Settings());
                }
            }
        }

        /* 6. DNS：三态 × 开关 × bootstrap 四模式 × 端口/SNI × 解析器写法 */
        String[] dnsPol = {Profile.DNS_PROXY, Profile.DNS_DIRECT, Profile.DNS_BLOCK, "bogus"};
        String[] bootModes = {"plain", "dot", "doh", "quic", ""};
        String[] resolvers = {
                "https://1.1.1.1/dns-query", "https://dns.google/dns-query",
                "tls://8.8.8.8", "8.8.8.8", "223.5.5.5:53", "",
                "https://dns.alidns.com/dns-query", "tls://dns.alidns.com:853"
        };
        for (String dp : dnsPol) {
            for (int on = 0; on < 2; on++) {
                for (String bm : bootModes) {
                    for (int bp = 0; bp < 2; bp++) {
                        Profile p = one(Node.VLESS, "tls");
                        p.dnsPolicy = dp;
                        Store.Settings s = new Store.Settings();
                        s.dnsEnabled = on == 1;
                        s.dnsHijack = on == 1;
                        s.dnsRemote = resolvers[(n >> 1) % resolvers.length];
                        s.dnsDomestic = resolvers[n % resolvers.length];
                        s.bootEnabled = on == 1;
                        s.bootMode = bm;
                        s.bootIp = bp == 1 ? "119.29.29.29" : "223.5.5.5";
                        s.bootPort = bp == 1 ? 8853 : 0;
                        s.bootSni = bp == 1 ? "dot.example.com" : "";
                        write("dns-" + dp + "-" + on + "-" + bm + "-" + bp, p, false, 0, s);
                    }
                }
            }
        }

        /* 7. 路由：预设 × 三态 × 规则字段全枚举 × 动作 × 反转 */
        String[] presets = {Profile.P_GLOBAL, Profile.P_BYPASS_CN, Profile.P_BYPASS_LAN,
                Profile.P_NONE, "bogus"};
        String[] fields = {Rule.F_DOMAIN, Rule.F_DOMAIN_SUFFIX, Rule.F_DOMAIN_KEYWORD,
                Rule.F_DOMAIN_REGEX, Rule.F_GEOSITE, Rule.F_IP, Rule.F_GEOIP, Rule.F_PORT,
                Rule.F_PROCESS, Rule.F_INBOUND, Rule.F_NETWORK, "bogus-field"};
        String[] actions = {Rule.A_PROXY, Rule.A_DIRECT, Rule.A_BLOCK, "bogus-action"};
        for (String preset : presets) {
            for (String fld : fields) {
                for (String act : actions) {
                    for (int inv = 0; inv < 2; inv++) {
                        Profile p = one(Node.VLESS, "tls");
                        p.preset = preset;
                        Rule r = new Rule(fld, "a.com,b.com", act);
                        r.invert = inv == 1;
                        p.rules.add(r);
                        Store.Settings s = new Store.Settings();
                        s.bypassPrivate = inv == 1;
                        write("rt-" + preset + "-" + fld + "-" + act + "-" + inv, p, false, 0, s);
                    }
                }
            }
        }
        /* 空值 / 逗号 / 空格 / 重复 / 大写 / geo 前缀 */
        String[][] raws = {
                {"", ""}, {" , , ", ""}, {"a.com,,b.com", " cn "}, {"A.COM,B.COM", "CN"},
                {"ext:geosite.dat:cn", "ext:geoip.dat:cn"}, {"geosite:cn", "geoip:cn"},
                {"10.0.0.0/8,fc00::/7", "::/0"}, {"a.com,a.com,a.com", "cn,cn"}
        };
        for (int i = 0; i < raws.length; i++) {
            Profile p = one(Node.VLESS, "tls");
            p.rules.add(new Rule(Rule.F_DOMAIN_SUFFIX, raws[i][0], Rule.A_DIRECT));
            p.rules.add(new Rule(Rule.F_GEOIP, raws[i][1], Rule.A_PROXY));
            write("rt-raw-" + i, p, false, 0, new Store.Settings());
        }

        /* 8. rawJson：合法 / ext 映射 / 空 / 坏 JSON */
        String[] rawsJson = {
                "{}",
                "{\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":\"freedom\"}]}",
                "{\"routing\":{\"rules\":[{\"type\":\"field\",\"ip\":[\"ext:geoip.dat:cn\"],"
                        + "\"outboundTag\":\"direct\"}]}}",
                "{\"routing\":{\"rules\":[{\"type\":\"field\","
                        + "\"domain\":[\"ext:geosite.dat:cn\",\"ext:geosite.dat:private\"]}]}}",
                "{\"dns\":{\"hosts\":{\"ext:geosite.dat:cn\":\"1.2.3.4\"}}}",
                "not json at all",
                "",
                null
        };
        for (int i = 0; i < rawsJson.length; i++) {
            Profile p = one(Node.VLESS, "tls");
            p.rawJson = rawsJson[i];
            write("raw-" + i, p, false, 0, new Store.Settings());
            write("raw-root-" + i, p, true, 0, new Store.Settings());
        }

        /* 9. 日志级别 / 空链 / 单节点字段缺省 */
        String[] levels = {"debug", "info", "warning", "error", "none", "bogus", ""};
        for (String lv : levels) {
            Profile p = one(Node.VLESS, "tls");
            p.logLevel = lv;
            write("log-" + lv, p, false, 0, new Store.Settings());
        }
        Profile empty = new Profile("empty");
        write("empty-chain", empty, false, 0, new Store.Settings());
        write("empty-chain-root", empty, true, 0, new Store.Settings());

        String[] sparce = {Node.VLESS, Node.VMESS, Node.TROJAN, Node.SS, Node.SOCKS, Node.HTTP};
        for (String proto : sparce) {
            Profile p = new Profile("sparse-" + proto);
            Node bare = new Node(proto, "1.2.3.4", 443);
            p.chain.add(bare);
            write("sparse-" + proto, p, false, 0, new Store.Settings());
        }

        System.out.println("cases=" + n);
    }

    private static String pad(int i) {
        return String.format("%03d", i);
    }

    private static void write(String name, Profile p, boolean root, int injectPort,
                              Store.Settings s) {
        String out;
        try {
            JSONObject c = Conf.build(p, s, root, injectPort);
            out = norm(c);
        } catch (Throwable t) {
            out = "EX:" + t.getClass().getName() + ":" + String.valueOf(t.getMessage())
                    .replace('\n', ' ').replace('\t', ' ');
        }
        System.out.println(pad(n++) + "-" + name + "\t" + out);
    }

    private static Profile one(String proto, String sec) {
        Profile p = new Profile(proto + "-" + sec);
        p.chain.add(mk(proto, "1.2.3.4", 443, sec));
        return p;
    }

    private static Node inject(String ini) {
        Node n = new Node(Node.INJECT, "", 0);
        n.ini = ini;
        return n;
    }

    private static void setNet(Profile p, String net) {
        Node n = p.chain.get(0);
        n.net = net;
        n.path = "/p";
        n.hostHdr = "cdn.example.com";
        n.serviceName = "svc";
        n.alpn = "h2,http/1.1";
        n.allowInsecure = true;
        n.fp = "chrome";
        n.pbk = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        n.sid = "0123abcd";
        n.spx = "/spx";
    }

    private static Node mk(String proto, String host, int port, String sec) {
        Node n = new Node(proto, host, port);
        n.uuid = "00000000-0000-0000-0000-000000000000";
        n.password = "password";
        n.user = "user";
        n.method = "aes-256-gcm";
        n.security = sec;
        n.sni = "s.example.com";
        n.fp = "chrome";
        n.pbk = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        n.sid = "0123abcd";
        n.spx = "/";
        n.net = "tcp";
        n.flow = "xtls-rprx-vision";
        n.serviceName = "svc";
        n.path = "/p";
        n.hostHdr = "cdn.example.com";
        n.alpn = "h2,http/1.1";
        n.allowInsecure = true;
        return n;
    }
}
