package com.lcs.tproxy.inject;

import com.lcs.tproxy.link.Links;
import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Rule;
import com.lcs.tproxy.model.Store;

import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * 链接解析 / 模型序列化的差分器：同一批输入分别喂给 1.8.2 与 2.0.0，
 * 用反射把对象的所有 public 字段（含嵌套 Node / List）规范化输出，逐行 diff。
 */
public final class ModelDiff {

    private static int n;

    public static void main(String[] args) {
        /* ---------- 1. 链接解析 ---------- */
        String[] links = {
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?encryption=none&security=tls&sni=s.example.com&fp=chrome&type=ws&path=%2Fws&host=cdn.example.com#n1",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?encryption=none&security=reality&sni=s.example.com&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&sid=0123abcd&spx=%2F&type=grpc&serviceName=svc&flow=xtls-rprx-vision#n2",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=none&type=tcp&headerType=http#n3",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=kcp&seed=x&headerType=wechat-video#n4",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=quic&quicSecurity=aes-128-gcm&key=k&headerType=srtp#n5",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=httpupgrade&path=%2Fhu&host=h.example.com#n6",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=xhttp&path=%2Fx&host=x.example.com&mode=auto#n7",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=h2&path=%2Fh2&host=h2.example.com&alpn=h2%2Chttp%2F1.1#n8",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=ws&security=xtls&allowInsecure=1#n9",
                "vless://00000000-0000-0000-0000-000000000000@[2001:db8::1]:443?security=tls&sni=v6.example.com#n10",
                "vless://bad-uuid@1.2.3.4:443#bad",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:notaport#bad2",
                "vless://00000000-0000-0000-0000-000000000000@:443#bad3",
                "vless://",
                "",
                "not-a-link",

                "vmess://eyJ2IjoiMiIsInBzIjoibjEiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImNkbi5leGFtcGxlLmNvbSIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJzLmV4YW1wbGUuY29tIiwiYWxwbiI6ImgyLGh0dHAvMS4xIn0=",
                "vmess://eyJ2IjoiMiIsInBzIjoibjIiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6IjAwMDAwMDAwLTAwMDAwMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwibmV0IjoiZ3JwYyIsInBhdGgiOiJzdmMiLCJ0bHMiOiJyZWFsaXR5IiwicGJrIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5QUJDREVGRyIsInNpZCI6IjAxMjNhYmNkIiwic3B4IjoiLyJ9",
                "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6IjAwMDAwMDAwLTAwMDAwMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn0=",
                "vmess://!!!notbase64!!!",
                "vmess://",

                "trojan://password@1.2.3.4:443?sni=s.example.com&type=ws&path=%2Ft#t1",
                "trojan://p%40ss@1.2.3.4:443?security=tls&allowInsecure=1&type=grpc&serviceName=g#t2",
                "trojan://password@1.2.3.4:443?type=tcp&headerType=none#t3",
                "trojan://",

                "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#s1",
                "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#s2",
                "ss://2022-blake3-aes-128-gcm:key@1.2.3.4:8388#s3",
                "ss://bad",

                "socks://1.2.3.4:1080#k1",
                "socks5://user:pass@1.2.3.4:1080#k2",
                "http://user:pass@1.2.3.4:8080#h1",
                "https://1.2.3.4:8443#h2",

                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=WS&security=TLS&SNI=S.EXAMPLE.COM#case",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=ws&path=/a%20b&host=a%2Cb#enc",
                "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?%E4%B8%AD%E6%96%87=%E5%80%BC#utf8",
        };
        for (int i = 0; i < links.length; i++) {
            Node x;
            try {
                x = Links.parseLink(links[i]);
            } catch (Throwable t) {
                x = null;
                out("link-" + i + "-EX", t.getClass().getName() + ":" + t.getMessage());
                continue;
            }
            if (x == null) {
                out("link-" + i, "NULL");
                continue;
            }
            out("link-" + i, fields(x));
            String back;
            try {
                back = Links.toLink(x);
            } catch (Throwable t) {
                back = "EX:" + t.getClass().getName() + ":" + t.getMessage();
            }
            out("link-" + i + "-back", back);
        }

        /* ---------- 2. 订阅文本 ---------- */
        String[] subs = {
                links[0] + "\n" + links[18],
                "vless://x\n\n\nvmess://y\n",
                java.util.Base64.getEncoder().encodeToString(
                        (links[0] + "\n" + links[18]).getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                "",
                "   ",
                "###comment\n" + links[0],
        };
        for (int i = 0; i < subs.length; i++) {
            try {
                List<Profile> ps = Links.parse(subs[i]);
                StringBuilder b = new StringBuilder("[");
                for (int j = 0; j < ps.size(); j++) {
                    if (j > 0) b.append(',');
                    b.append(fields(ps.get(j)));
                }
                out("sub-" + i, b.append(']').toString());
            } catch (Throwable t) {
                out("sub-" + i + "-EX", t.getClass().getName() + ":" + t.getMessage());
            }
        }

        /* ---------- 3. Node / Profile 序列化往返 ---------- */
        Node node = sample();
        for (int i = 0; i < 4; i++) {
            out("node-json-" + i, fields(node));
            JSONObject j = node.toJson();
            out("node-jsontext-" + i, norm(j));
            node = Node.fromJson(j);
        }
        node.udpNode = sample();
        node.udpViaInject = false;
        JSONObject nj = node.toJson();
        out("node-udp-json", norm(nj));
        out("node-udp-back", fields(Node.fromJson(nj)));

        Profile p = new Profile("p1");
        p.chain.add(sample());
        p.chain.add(sample());
        p.rules.add(new Rule(Rule.F_DOMAIN_SUFFIX, "a.com,b.com", Rule.A_DIRECT));
        p.rules.add(new Rule(Rule.F_GEOIP, "cn", Rule.A_PROXY));
        p.rules.add(new Rule(Rule.F_INBOUND, "socks-in", Rule.A_BLOCK));
        p.rules.get(0).invert = true;
        p.udpPolicy = Profile.UDP_PROXY;
        p.quicPolicy = Profile.UDP_BLOCK;
        p.dnsPolicy = Profile.DNS_DIRECT;
        p.v6 = Profile.V6_BLOCK;
        p.preset = Profile.P_BYPASS_CN;
        for (int i = 0; i < 3; i++) {
            out("prof-json-" + i, norm(p.toJson()));
            p = Profile.fromJson(p.toJson());
        }

        /* ---------- 4. ini / json 配置导入 ---------- */
        String[] inis = {
                "https_ip=192.168.1.1;\nhttps_port=443;\nhttps_first=\"CONNECT [H] HTTP/1.1\\r\\nHost: [H]\\r\\n\";\n",
                "http_ip=10.0.0.1;http_port=80;http_first=\"[M] [U] [V]\\r\\nHost: [H]\\r\\n\";\n",
                "https_ip=1.1.1.1;\nhttps_first=\"CONNECT [H] HTTP/1.1\\r\\n\";\nmethods=GET,POST\n",
                "",
                "garbage",
        };
        for (int i = 0; i < inis.length; i++) {
            try {
                Profile q = Links.fromIni(inis[i]);
                out("ini-" + i, fields(q));
            } catch (Throwable t) {
                out("ini-" + i + "-EX", t.getClass().getName() + ":" + t.getMessage());
            }
        }

        String[] cfgs = {
                "{\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"1.2.3.4\",\"port\":443,\"users\":[{\"id\":\"00000000-0000-0000-0000-000000000000\"}]}]},\"streamSettings\":{\"network\":\"ws\",\"security\":\"tls\",\"wsSettings\":{\"path\":\"/w\",\"headers\":{\"Host\":\"h.com\"}}}}]}",
                "{\"outbounds\":[{\"tag\":\"a\",\"protocol\":\"vmess\",\"settings\":{\"vnext\":[{\"address\":\"1.2.3.4\",\"port\":443,\"users\":[{\"id\":\"00000000-0000-0000-0000-000000000000\",\"alterId\":0,\"security\":\"auto\"}]}]}}]}",
                "{\"outbounds\":[{\"protocol\":\"trojan\",\"settings\":{\"servers\":[{\"address\":\"1.2.3.4\",\"port\":443,\"password\":\"p\"}]}}]}",
                "{\"outbounds\":[{\"protocol\":\"shadowsocks\",\"settings\":{\"servers\":[{\"address\":\"1.2.3.4\",\"port\":8388,\"method\":\"aes-256-gcm\",\"password\":\"p\"}]}}]}",
                "{}", "not json", "",
                "{\"outbounds\":[{\"protocol\":\"freedom\"}]}",
        };
        for (int i = 0; i < cfgs.length; i++) {
            try {
                Profile q = Links.fromJsonConfig(cfgs[i]);
                out("cfg-" + i, q == null ? "NULL" : fields(q));
            } catch (Throwable t) {
                out("cfg-" + i + "-EX", t.getClass().getName() + ":" + t.getMessage());
            }
        }

        System.out.println("cases=" + n);
    }

    private static Node sample() {
        Node x = new Node(Node.VLESS, "1.2.3.4", 443);
        x.name = "样本";
        x.uuid = "00000000-0000-0000-0000-000000000000";
        x.password = "p@ss";
        x.user = "u";
        x.method = "aes-256-gcm";
        x.alterId = 0;
        x.vmessScy = "auto";
        x.vmessPcs = "";
        x.flow = "xtls-rprx-vision";
        x.security = "reality";
        x.sni = "s.example.com";
        x.alpn = "h2,http/1.1";
        x.fp = "chrome";
        x.pbk = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        x.sid = "0123abcd";
        x.spx = "/";
        x.allowInsecure = true;
        x.net = "grpc";
        x.path = "/p";
        x.hostHdr = "h.com";
        x.serviceName = "svc";
        x.headerType = "none";
        x.quicSecurity = "none";
        x.uot = true;
        x.ini = "a=b;";
        x.remark = "r";
        return x;
    }

    /* ---------------------------------------------------------------- 反射 */

    /** 不参与对拍的字段：2.0.0 新增的三个（旧版没有，必然只在一边出现），
     *  以及 Profile 的随机 UUID（每次生成都不同，属于噪声而非语义差异）。 */
    private static final java.util.Set<String> SKIP =
            new java.util.HashSet<String>(java.util.Arrays.asList(
                    "udpSrcProfile", "udpSrcIndex", "udpSrcFp", "id"));

    private static String fields(Object o) {
        if (o == null) return "null";
        StringBuilder b = new StringBuilder("{");
        List<Field> fs = new ArrayList<Field>();
        for (Field f : o.getClass().getFields()) {
            if (!Modifier.isStatic(f.getModifiers()) && !SKIP.contains(f.getName())) fs.add(f);
        }
        Collections.sort(fs, (a, c) -> a.getName().compareTo(c.getName()));
        for (int i = 0; i < fs.size(); i++) {
            Field f = fs.get(i);
            if (i > 0) b.append(',');
            b.append(f.getName()).append('=');
            try {
                b.append(val(f.get(o)));
            } catch (Exception e) {
                b.append("<err>");
            }
        }
        return b.append('}').toString();
    }

    private static String val(Object v) {
        if (v == null) return "null";
        if (v instanceof Node) return fields(v);
        if (v instanceof Rule) return fields(v);
        if (v instanceof List) {
            List<?> l = (List<?>) v;
            StringBuilder b = new StringBuilder("[");
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) b.append(',');
                b.append(val(l.get(i)));
            }
            return b.append(']').toString();
        }
        if (v instanceof java.util.Map) {
            java.util.Map<?, ?> m = (java.util.Map<?, ?>) v;
            List<String> ks = new ArrayList<String>();
            for (Object k : m.keySet()) ks.add(String.valueOf(k));
            Collections.sort(ks);
            StringBuilder b = new StringBuilder("{");
            for (int i = 0; i < ks.size(); i++) {
                if (i > 0) b.append(',');
                b.append(ks.get(i)).append('=').append(val(m.get(ks.get(i))));
            }
            return b.append('}').toString();
        }
        return String.valueOf(v);
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
                if (i > 0) b.append(',');
                b.append('"').append(keys.get(i)).append("\":").append(norm(j.opt(keys.get(i))));
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
        if (o instanceof String) {
            return '"' + ((String) o).replace("\\", "\\\\").replace("\"", "\\\"")
                    .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"';
        }
        return String.valueOf(o);
    }

    private static void out(String name, String v) {
        System.out.println(String.format("%03d", n++) + "-" + name + "\t"
                + v.replace('\n', ' ').replace('\r', ' ').replace('\t', ' '));
    }
}
