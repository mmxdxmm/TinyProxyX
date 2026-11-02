package com.lcs.tproxy.inject;

import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Rule;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.xray.Conf;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/** 把配置矩阵写成文件，交给真实 xray `run -test` 逐份验收。 */
public final class DumpConfigs {

    private static File dir;
    private static int n;

    public static void main(String[] args) throws Exception {
        dir = new File(args.length > 0 ? args[0] : "/tmp/tpx-configs");
        dir.mkdirs();
        for (File f : dir.listFiles()) f.delete();

        String[] protocols = {Node.VLESS, Node.VMESS, Node.TROJAN, Node.SS, Node.SOCKS, Node.HTTP};
        String[] nets = {"tcp", "ws", "grpc", "h2", "http", "httpupgrade", "xhttp", "kcp", "quic"};
        String[] secs = {"none", "tls", "reality"};

        for (String proto : protocols) {
            for (String net : nets) {
                for (String sec : secs) {
                    /* 这两类组合是 xray 自己拒绝的，不是构建器的输出问题：
                     *   - 公网明文 VLESS/Trojan（chainWarning 已经明确提示用户改 TLS）
                     *   - REALITY 只支持 RAW / XHTTP / gRPC 三种承载
                     * 验收矩阵里用合法输入，避免把「用户配置非法」算成生成器失败。 */
                    if ("none".equals(sec) && !("socks".equals(proto) || "http".equals(proto)
                            || "vmess".equals(proto) || "ss".equals(proto))) {
                        Profile p = one(proto, sec, "192.168.1.10");
                        p.chain.get(0).net = net;
                        p.chain.get(0).path = "/p";
                        p.chain.get(0).hostHdr = "cdn.example.com";
                        p.chain.get(0).serviceName = "svc";
                        write("p-" + proto + "-" + net + "-" + sec, p, false, 0);
                        write("root-" + proto + "-" + net + "-" + sec, p, true, 0);
                        continue;
                    }
                    if ("reality".equals(sec) && ("ws".equals(net) || "httpupgrade".equals(net)
                            || "kcp".equals(net))) {
                        continue;
                    }
                    Profile p = one(proto, sec);
                    p.chain.get(0).net = net;
                    p.chain.get(0).path = "/p";
                    p.chain.get(0).hostHdr = "cdn.example.com";
                    p.chain.get(0).serviceName = "svc";
                    write("p-" + proto + "-" + net + "-" + sec, p, false, 0);
                    write("root-" + proto + "-" + net + "-" + sec, p, true, 0);
                }
            }
        }

        /* 链式 + 注入 + UDP 转换 */
        Profile chain = new Profile("chain");
        chain.chain.add(node(Node.VLESS, "192.168.1.10", 443, "tls"));
        chain.chain.add(node(Node.TROJAN, "1.2.3.4", 8443, "reality"));
        write("chain-2hop", chain, false, 0);
        write("chain-2hop-root", chain, true, 0);

        Profile inj = new Profile("inject");
        Node hop = new Node(Node.INJECT, "", 0);
        hop.ini = "https_ip=192.168.1.1;\nhttps_port=443;\nhttps_first=\"CONNECT [H] HTTP/1.1\\r\\nHost: [H]\\r\\n\";";
        inj.chain.add(hop);
        write("inject-only", inj, false, 45871);
        write("inject-only-root", inj, true, 45871);

        Profile injChain = new Profile("inject-chain");
        Node ih = new Node(Node.INJECT, "", 0);
        ih.ini = "https_ip=192.168.1.1;";
        injChain.chain.add(ih);
        injChain.chain.add(node(Node.VLESS, "192.168.1.10", 443, "tls"));
        write("inject-chain", injChain, false, 45872);

        Profile udp = new Profile("udp");
        Node uh = new Node(Node.INJECT, "", 0);
        uh.ini = "https_ip=192.168.1.1;";
        uh.udpNode = node(Node.VLESS, "192.168.1.11", 443, "tls");
        uh.udpViaInject = true;
        udp.chain.add(uh);
        udp.udpPolicy = Profile.UDP_PROXY;
        udp.quicPolicy = Profile.UDP_PROXY;
        write("udp-via-inject", udp, false, 45873);
        uh.udpViaInject = false;
        write("udp-direct", udp, false, 45873);

        Profile udpTcp = new Profile("udp-tcp");
        Node ut = new Node(Node.INJECT, "", 0);
        ut.ini = "https_ip=192.168.1.1;";
        ut.udpNode = node(Node.TROJAN, "192.168.1.12", 443, "tls");
        ut.udpNode.uot = true;
        udpTcp.chain.add(ut);
        udpTcp.udpPolicy = Profile.UDP_PROXY;
        udpTcp.quicPolicy = Profile.UDP_PROXY;
        write("udp-trojan-uot", udpTcp, false, 45874);

        /* 预设 / 规则 / IPv6 / DNS 三态 */
        String[] presets = {Profile.P_GLOBAL, Profile.P_BYPASS_CN, Profile.P_BYPASS_LAN};
        String[] dnsPolicies = {Profile.DNS_PROXY, Profile.DNS_DIRECT, Profile.DNS_BLOCK};
        String[] v6s = {Profile.V6_PROXY, Profile.V6_DIRECT, Profile.V6_BLOCK};
        for (String preset : presets) {
            for (String dns : dnsPolicies) {
                for (String v6 : v6s) {
                    Profile p = one(Node.VLESS, "tls");
                    p.preset = preset;
                    p.dnsPolicy = dns;
                    p.v6 = v6;
                    p.udpPolicy = Profile.UDP_DIRECT;
                    p.quicPolicy = Profile.UDP_BLOCK;
                    p.rules.add(new Rule(Rule.F_DOMAIN_SUFFIX, "a.com,b.com", Rule.A_DIRECT));
                    p.rules.add(new Rule(Rule.F_DOMAIN_KEYWORD, "ads", Rule.A_BLOCK));
                    p.rules.add(new Rule(Rule.F_GEOSITE, "cn", Rule.A_DIRECT));
                    p.rules.add(new Rule(Rule.F_GEOIP, "cn", Rule.A_DIRECT));
                    p.rules.add(new Rule(Rule.F_PORT, "8080,8443", Rule.A_PROXY));
                    p.rules.add(new Rule(Rule.F_NETWORK, "udp", Rule.A_BLOCK));
                    p.rules.add(new Rule(Rule.F_PROCESS, "com.example", Rule.A_DIRECT));
                    p.rules.add(new Rule(Rule.F_INBOUND, "socks-in", Rule.A_PROXY));
                    write("route-" + preset + "-" + dns + "-" + v6, p, false, 0);
                }
            }
        }

        Profile ruleInv = one(Node.VLESS, "tls");
        Rule inv = new Rule(Rule.F_IP, "10.0.0.0/8", Rule.A_DIRECT);
        inv.invert = true;
        ruleInv.rules.add(inv);
        ruleInv.rules.add(new Rule(Rule.F_DOMAIN_REGEX, "^ad\\..*", Rule.A_BLOCK));
        write("rule-invert-regex", ruleInv, false, 0);

        /* mux / sniff / allowLan / 自定义端口 */
        Profile mux = one(Node.VMESS, "tls");
        mux.mux = true;
        mux.sniff = false;
        Store.Settings s = new Store.Settings();
        s.allowLan = true;
        s.socksPort = 20808;
        s.httpPort = 20809;
        s.dnsEnabled = true;
        s.dnsRemote = "https://1.1.1.1/dns-query";
        s.dnsDomestic = "https://223.5.5.5/dns-query";
        writeWith("mux-sniff-lan-dns", mux, s, false, 0);

        /* 完整 JSON 原样运行（含 ext: 映射） */
        Profile raw = new Profile("raw");
        raw.rawJson = "{\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":\"vless\",\"settings\":"
                + "{\"vnext\":[{\"address\":\"192.168.1.10\",\"port\":443,\"users\":[{\"id\":"
                + "\"00000000-0000-0000-0000-000000000000\",\"encryption\":\"none\"}]}]},"
                + "\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\"}},"
                + "{\"tag\":\"direct\",\"protocol\":\"freedom\"},{\"tag\":\"block\",\"protocol\":\"blackhole\"}],"
                + "\"routing\":{\"rules\":[{\"type\":\"field\",\"ip\":[\"ext:geoip.dat:cn\"],"
                + "\"outboundTag\":\"direct\"},{\"type\":\"field\",\"outboundTag\":\"proxy\"}]}}";
        write("raw-json-ext", raw, false, 0);
        raw.rawJson = raw.rawJson.replace("\"ip\":[\"ext:geoip.dat:cn\"]",
                "\"domain\":[\"ext:geosite.dat:cn\",\"ext:geosite.dat:private\"]");
        write("raw-json-geosite", raw, false, 0);

        System.out.println("written=" + n + " dir=" + dir);
    }

    private static Profile one(String proto, String sec) {
        return one(proto, sec, "1.2.3.4");
    }

    private static Profile one(String proto, String sec, String host) {
        Profile p = new Profile(proto + "-" + sec);
        p.chain.add(node(proto, host, 443, sec));
        return p;
    }

    private static Node node(String proto, String host, int port, String sec) {
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
        return n;
    }

    private static void write(String name, Profile p, boolean root, int injectPort) throws Exception {
        writeWith(name, p, new Store.Settings(), root, injectPort);
    }

    private static void writeWith(String name, Profile p, Store.Settings s, boolean root, int injectPort)
            throws Exception {
        try {
            JSONObject c = Conf.build(p, s, root, injectPort);
            File f = new File(dir, String.format("%03d-%s.json", n++, name));
            FileOutputStream out = new FileOutputStream(f);
            out.write(c.toString(2).getBytes(StandardCharsets.UTF_8));
            out.close();
        } catch (Exception e) {
            System.out.println("BUILD FAIL " + name + ": " + e);
        }
    }
}
