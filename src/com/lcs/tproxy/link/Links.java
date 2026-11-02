package com.lcs.tproxy.link;

import android.util.Base64;

import com.lcs.tproxy.inject.Ini;
import com.lcs.tproxy.model.Kinds;
import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Rule;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Share-link and raw-config importer/exporter (v2rayNG compatible surface). */
public class Links {

    public static final String DEFAULT_TAG = "proxy";

    /** Parse any pasted blob: one or more share links, or a full xray/v2ray json config. */
    public static List<Profile> parse(String text) {
        List<Profile> out = new ArrayList<Profile>();
        if (text == null) return out;
        String t = text.trim();
        if (t.startsWith("\uFEFF")) t = t.substring(1).trim();
        if (looksLegacy(t)) {
            Profile p = fromIni(t);
            if (p != null) out.add(p);
            return out;
        }
        if (t.startsWith("{")) {
            Profile p = fromJsonConfig(t);
            if (p != null) out.add(p);
            return out;
        }
        String[] lines = t.split("[\\r\\n]+");
        for (String line : lines) {
            line = line.trim();
            if (line.length() < 8) continue;
            Node n = parseLink(line);
            if (n != null) {
                Profile p = new Profile(n.title());
                p.chain.add(n);
                out.add(p);
            }
        }
        return out;
    }

    /** the old key=value; config (Socks5ProxyConfig) -- the legacy inject dialect */
    public static boolean looksLegacy(String t) {
        String l = t.toLowerCase();
        return l.contains("listen_port") || l.contains("http_first") || l.contains("https_first")
                || l.contains("http_ip=") || l.contains("https_ip=");
    }

    public static Profile fromIni(String text) {
        Ini c = Ini.parse(text);
        Node n = new Node();
        n.type = Node.INJECT;
        n.ini = text;
        n.host = c.httpsIp.length() > 0 ? c.httpsIp : c.httpIp;
        n.port = c.httpsIp.length() > 0 ? c.httpsPort : c.httpPort;
        n.security = c.httpsDispose ? "tls" : "none";
        n.name = c.name.length() > 0 ? c.name : (n.host.length() > 0 ? "注入 " + n.host : "注入配置");
        Profile p = new Profile(n.name);
        p.chain.add(n);
        return p;
    }

    public static Node parseLink(String s) {
        try {
            int i = s.indexOf("://");
            if (i <= 0) return null;
            String scheme = s.substring(0, i).toLowerCase();
            String body = s.substring(i + 3);
            String name = "";
            int hash = body.indexOf('#');
            if (hash >= 0) {
                name = URLDecoder.decode(body.substring(hash + 1), "UTF-8");
                body = body.substring(0, hash);
            }
            /* 首字母 switch 直接跳表，不再是一条五段的 startsWith 链。 */
            switch (scheme.charAt(0)) {
                case 'v':
                    if ("vmess".equals(scheme)) return parseVmess(body, name);
                    if (scheme.startsWith("vless")) return parseUrlStyle(scheme, body, name);
                    return null;
                case 's':
                    if (scheme.startsWith("ss")) return parseSs(scheme, body, name);
                    if (scheme.startsWith("socks")) return parseSocks(body, name);
                    return null;
                case 'h':
                    return scheme.equals("http") || scheme.equals("https")
                            ? parseHttp(scheme, body, name) : null;
                case 't':
                    return scheme.startsWith("trojan") ? parseUrlStyle(scheme, body, name) : null;
                default:
                    return null;
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /* ---------------- vless / trojan uri ---------------- */

    private static Node parseUrlStyle(String scheme, String body, String name) {
        String query = "";
        int q = body.indexOf('?');
        String main = body;
        if (q >= 0) {
            query = body.substring(q + 1);
            main = body.substring(0, q);
        }
        String userInfo = "";
        int at = main.lastIndexOf('@');
        if (at >= 0) {
            userInfo = urlDecode(main.substring(0, at));
            main = main.substring(at + 1);
        }
        String host;
        int port = 443;
        if (main.startsWith("[")) {
            int e = main.indexOf(']');
            host = main.substring(1, e);
            int c = main.indexOf(':', e);
            if (c > 0) port = parseInt(main.substring(c + 1), 443);
        } else {
            int c = main.lastIndexOf(':');
            if (c >= 0) {
                host = main.substring(0, c);
                port = parseInt(main.substring(c + 1), 443);
            } else host = main;
        }
        Map<String, String> p = queryMap(query);
        Node n = new Node();
        n.host = host;
        n.port = port;
        n.name = name.length() > 0 ? name : host;
        String baseScheme = scheme;
        int plus = scheme.indexOf('+');
        if (plus > 0) baseScheme = scheme.substring(0, plus);

        if (baseScheme.equals("vless")) {
            n.type = Node.VLESS;
            n.uuid = userInfo;
            n.flow = opt(p, "flow", "");
            n.net = opt(p, "type", "tcp");
            applyTransport(n, p);
            applyTls(n, p, scheme);
        } else if (baseScheme.equals("trojan")) {
            n.type = Node.TROJAN;
            n.password = userInfo;
            n.security = "tls";
            n.net = opt(p, "type", "tcp");
            applyTransport(n, p);
            applyTls(n, p, scheme);
        } else {
            return null;
        }
        return n;
    }

    private static void applyTransport(Node n, Map<String, String> p) {
        String type = opt(p, "type", "tcp");
        n.net = type;
        n.path = opt(p, "path", "");
        n.hostHdr = opt(p, "host", "");
        n.serviceName = opt(p, "serviceName", "");
        n.headerType = opt(p, "headerType", "none");
        if (n.path.isEmpty() && type.equals("grpc")) n.path = "";
    }

    private static void applyTls(Node n, Map<String, String> p, String scheme) {
        String sec = opt(p, "security", "");
        if (sec.isEmpty()) sec = scheme.contains("reality") ? "reality" : (scheme.contains("tls") ? "tls" : "none");
        n.security = sec;
        n.sni = opt(p, "sni", opt(p, "peer", ""));
        n.alpn = opt(p, "alpn", "");
        n.fp = opt(p, "fp", "");
        n.pbk = opt(p, "pbk", "");
        n.sid = opt(p, "sid", "");
        n.spx = opt(p, "spx", "/");
        n.allowInsecure = "1".equals(opt(p, "allowInsecure", "0"));
    }

    /* ---------------- vmess ---------------- */

    private static Node parseVmess(String body, String name) {
        String json;
        try {
            json = b64(body);
        } catch (Exception e) {
            return null;
        }
        try {
            JSONObject o = new JSONObject(json);
            Node n = new Node();
            n.type = Node.VMESS;
            n.host = o.optString("add", "");
            n.port = parseInt(o.optString("port", "443"), 443);
            n.uuid = o.optString("id", "");
            n.alterId = parseInt(o.optString("aid", "0"), 0);
            n.net = o.optString("net", "tcp");
            n.headerType = o.optString("type", "none");
            n.hostHdr = o.optString("host", "");
            n.path = o.optString("path", "");
            n.vmessScy = o.optString("scy", "auto");
            n.vmessPcs = o.optString("pcs", "");
            String tls = o.optString("tls", "");
            n.security = tls.isEmpty() || "none".equalsIgnoreCase(tls)
                    ? "none" : ("reality".equalsIgnoreCase(tls) ? "reality" : "tls");
            n.sni = o.optString("sni", "");
            n.alpn = o.optString("alpn", "");
            n.fp = o.optString("fp", "");
            n.allowInsecure = "1".equals(o.optString("insecure", "0"))
                    || o.optBoolean("insecure", false);
            String ps = o.optString("ps", "");
            n.name = name.length() > 0 ? name : (ps.length() > 0 ? ps : n.host);
            if (n.host.isEmpty()) return null;
            return n;
        } catch (Exception e) {
            return null;
        }
    }

    /* ---------------- shadowsocks ---------------- */

    private static Node parseSs(String scheme, String body, String name) {
        Node n = new Node();
        n.type = Node.SS;
        String rest;
        Map<String, String> p = new HashMap<String, String>();
        int q = body.indexOf('?');
        if (q >= 0) {
            p = queryMap(body.substring(q + 1));
            body = body.substring(0, q);
        }
        if (body.contains("@")) {
            int at = body.lastIndexOf('@');
            String cred = body.substring(0, at);
            rest = body.substring(at + 1);
            if (!cred.contains(":")) cred = b64(cred);
            int c = cred.indexOf(':');
            n.method = c > 0 ? cred.substring(0, c) : "aes-256-gcm";
            n.password = c > 0 ? cred.substring(c + 1) : cred;
        } else {
            String dec = b64(body);
            int at = dec.lastIndexOf('@');
            if (at < 0) return null;
            String cred = dec.substring(0, at);
            rest = dec.substring(at + 1);
            int c = cred.indexOf(':');
            n.method = c > 0 ? cred.substring(0, c) : "aes-256-gcm";
            n.password = c > 0 ? cred.substring(c + 1) : cred;
        }
        int c = rest.lastIndexOf(':');
        if (c < 0) return null;
        n.host = rest.substring(0, c);
        n.port = parseInt(rest.substring(c + 1), 8388);
        n.name = name.length() > 0 ? name : n.host;
        String plugin = opt(p, "plugin", "");
        if (!plugin.isEmpty()) n.remark = "plugin=" + plugin;
        return n;
    }

    /* ---------------- socks / http ---------------- */

    private static Node parseSocks(String body, String name) {
        String query = "";
        int q = body.indexOf('?');
        if (q >= 0) {
            query = body.substring(q + 1);
            body = body.substring(0, q);
        }
        return hostPortNode(Node.SOCKS, body, name, query);
    }

    private static Node parseHttp(String scheme, String body, String name) {
        String query = "";
        int q = body.indexOf('?');
        if (q >= 0) {
            query = body.substring(q + 1);
            body = body.substring(0, q);
        }
        int slash = body.indexOf('/');
        if (slash >= 0) body = body.substring(0, slash);
        Node n = hostPortNode(Node.HTTP, body, name, query);
        if (n != null && "https".equals(scheme)) {
            n.security = "tls";
            if (n.sni.isEmpty()) n.sni = n.host;
        }
        return n;
    }

    private static Node hostPortNode(String type, String body, String name, String query) {
        String user = "";
        String pass = "";
        String main = body;
        int at = main.lastIndexOf('@');
        if (at >= 0) {
            String cred = main.substring(0, at);
            main = main.substring(at + 1);
            if (!cred.contains(":")) cred = b64(cred);
            int c = cred.indexOf(':');
            if (c >= 0) {
                user = cred.substring(0, c);
                pass = cred.substring(c + 1);
            } else user = cred;
        }
        String host;
        int port;
        int c = main.lastIndexOf(':');
        if (c < 0) return null;
        host = main.substring(0, c);
        port = parseInt(main.substring(c + 1), 1080);
        if (host.isEmpty()) return null;
        Node n = new Node(type, host, port);
        n.user = user;
        n.password = pass;
        n.name = name.length() > 0 ? name : host;
        Map<String, String> p = queryMap(query);
        String sec = opt(p, "security", "");
        if (sec.equals("tls") || "1".equals(opt(p, "tls", "0"))) {
            n.security = "tls";
            n.sni = opt(p, "sni", host);
        }
        return n;
    }

    /* ---------------- full json config ---------------- */

    public static Profile fromJsonConfig(String text) {
        try {
            JSONObject root = new JSONObject(text);
            Profile p = new Profile("导入配置");
            p.rawJson = text;
            JSONArray outs = root.optJSONArray("outbounds");
            List<Node> nodes = new ArrayList<Node>();
            if (outs != null && outs.length() > 0) {
                Map<String, JSONObject> byTag = new HashMap<String, JSONObject>();
                List<JSONObject> usable = new ArrayList<JSONObject>();
                for (int i = 0; i < outs.length(); i++) {
                    JSONObject o = outs.optJSONObject(i);
                    if (o == null) continue;
                    String proto = o.optString("protocol", "");
                    if (proto.equals("freedom") || proto.equals("blackhole") || proto.equals("dns")) continue;
                    String tag = o.optString("tag", "");
                    if (tag.length() > 0) byTag.put(tag, o);
                    usable.add(o);
                }
                if (!usable.isEmpty()) {
                    JSONObject first = usable.get(0);
                    for (JSONObject o : usable) if (DEFAULT_TAG.equals(o.optString("tag"))) first = o;
                    // walk the dialer chain: first is the exit, each proxySettings.tag is the next hop inward
                    JSONObject cur = first;
                    List<Node> stack = new ArrayList<Node>();
                    int guard = 0;
                    while (cur != null && guard++ < 16) {
                        Node n = fromOutbound(cur);
                        if (n != null) stack.add(0, n);
                        JSONObject ps = cur.optJSONObject("proxySettings");
                        String t = ps != null ? ps.optString("tag", "") : "";
                        cur = t.length() > 0 ? byTag.get(t) : null;
                    }
                    nodes.addAll(stack);
                }
            }
            if (nodes.isEmpty()) return null;
            p.chain.addAll(nodes);
            p.name = root.optString("remarks", nodes.get(nodes.size() - 1).title());
            JSONObject routing = root.optJSONObject("routing");
            if (routing != null) {
                JSONArray rs = routing.optJSONArray("rules");
                if (rs != null) {
                    for (int i = 0; i < rs.length(); i++) {
                        JSONObject r = rs.optJSONObject(i);
                        if (r == null) continue;
                        Rule rule = fromRoutingRule(r);
                        if (rule != null) p.rules.add(rule);
                    }
                }
                p.preset = p.rules.isEmpty() ? Profile.P_GLOBAL : Profile.P_NONE;
            } else p.preset = Profile.P_GLOBAL;
            JSONObject dns = root.optJSONObject("dns");
            if (dns != null) {
                JSONArray srvs = dns.optJSONArray("servers");
                if (srvs != null && srvs.length() > 0) {
                    Object first = srvs.opt(0);
                    if (first instanceof String) {
                        p.dnsRemote = (String) first;
                        p.overrideDns = true;
                    }
                }
            }
            return p;
        } catch (Exception e) {
            return null;
        }
    }

    private interface OutFn {
        Node make(JSONObject o, JSONObject s, JSONObject ss) throws Exception;
    }

    /** 协议 → 出站解析器。数组下标就是 Kinds 里的协议 id，不再逐条 equals。 */
    private static final OutFn[] OUT = new OutFn[Kinds.TYPE_N];

    static {
        OUT[Kinds.VLESS] = Links::vnext;
        OUT[Kinds.VMESS] = Links::vnext;
        OUT[Kinds.TROJAN] = Links::server;
        OUT[Kinds.SS] = Links::shadowsocks;
        OUT[Kinds.SOCKS] = Links::server;
        OUT[Kinds.HTTP] = Links::server;
        OUT[Kinds.INJECT] = (o, s, ss) -> null;
        OUT[Kinds.UNKNOWN] = (o, s, ss) -> null;
    }

    private static Node fromOutbound(JSONObject o) {
        Node n = new Node();
        JSONObject s = o.optJSONObject("settings");
        JSONObject ss = o.optJSONObject("streamSettings");
        int kind = Kinds.type(o.optString("protocol", ""));
        n.type = o.optString("protocol", "");
        Node parsed;
        try {
            parsed = OUT[kind].make(o, s, ss);
        } catch (Exception e) {
            return null;
        }
        if (parsed == null) return null;
        n = parsed;
        n.kind();                                    /* 预热缓存，后面取值不再比字符串 */
        if (ss != null) {
            n.net = ss.optString("network", "tcp");
            n.security = ss.optString("security", "none");
            JSONObject tls = ss.optJSONObject("tlsSettings");
            if (tls != null) {
                n.sni = tls.optString("serverName", "");
                n.allowInsecure = tls.optBoolean("allowInsecure", false);
                JSONArray alpn = tls.optJSONArray("alpn");
                if (alpn != null && alpn.length() > 0) n.alpn = alpn.optString(0);
                n.fp = tls.optString("fingerprint", "");
            }
            JSONObject reality = ss.optJSONObject("realitySettings");
            if (reality != null) {
                n.pbk = reality.optString("publicKey", "");
                n.sid = reality.optString("shortId", "");
                n.spx = reality.optString("spiderX", "/");
                n.sni = reality.optString("serverName", n.sni);
                n.fp = reality.optString("fingerprint", n.fp);
                n.security = "reality";
            }
            JSONObject tcp = ss.optJSONObject("tcpSettings");
            if (tcp != null) {
                JSONObject header = tcp.optJSONObject("header");
                if (header != null) {
                    n.headerType = header.optString("type", n.headerType);
                    JSONObject req = header.optJSONObject("request");
                    if (req != null) {
                        JSONArray paths = req.optJSONArray("path");
                        if (paths != null && paths.length() > 0) n.path = paths.optString(0);
                        JSONObject hs = req.optJSONObject("headers");
                        JSONArray hosts = hs != null ? hs.optJSONArray("Host") : null;
                        if (hosts != null && hosts.length() > 0) n.hostHdr = hosts.optString(0);
                    }
                }
            }
            JSONObject ws = ss.optJSONObject("wsSettings");
            if (ws != null) {
                n.path = ws.optString("path", "");
                n.hostHdr = ws.optString("host", "");
                JSONObject h = ws.optJSONObject("headers");
                if (n.hostHdr.isEmpty() && h != null) n.hostHdr = h.optString("Host", "");
            }
            JSONObject grpc = ss.optJSONObject("grpcSettings");
            if (grpc != null) {
                n.serviceName = grpc.optString("serviceName", "");
                n.hostHdr = grpc.optString("authority", n.hostHdr);
            }
            JSONObject h2 = ss.optJSONObject("httpSettings");
            if (h2 != null) {
                n.path = h2.optString("path", n.path);
                JSONArray hosts = h2.optJSONArray("host");
                if (hosts != null && hosts.length() > 0) n.hostHdr = hosts.optString(0);
            }
            JSONObject hu = ss.optJSONObject("httpupgradeSettings");
            if (hu != null) {
                n.path = hu.optString("path", n.path);
                n.hostHdr = hu.optString("host", n.hostHdr);
            }
            JSONObject xh = ss.optJSONObject("xhttpSettings");
            if (xh != null) {
                n.path = xh.optString("path", "");
                n.hostHdr = xh.optString("host", "");
            }
            JSONObject kcp = ss.optJSONObject("kcpSettings");
            if (kcp != null) {
                JSONObject hd = kcp.optJSONObject("header");
                if (hd != null) n.headerType = hd.optString("type", n.headerType);
            }
            JSONObject quic = ss.optJSONObject("quicSettings");
            if (quic != null) {
                n.quicSecurity = quic.optString("security", "none");
                n.path = quic.optString("key", n.path);
                JSONObject hd = quic.optJSONObject("header");
                if (hd != null) n.headerType = hd.optString("type", n.headerType);
            }
        }
        n.name = o.optString("tag", n.host);
        return n.host == null || n.host.isEmpty() ? null : n;
    }

    /** vless / vmess：vnext 形态（新）与扁平 settings（Xray 26）两种都认。 */
    private static Node vnext(JSONObject o, JSONObject s, JSONObject ss) {
        Node n = new Node();
        n.type = o.optString("protocol", "");
        JSONArray v = s != null ? s.optJSONArray("vnext") : null;
        if (v != null && v.length() > 0) {
            JSONObject vn = v.optJSONObject(0);
            n.host = vn.optString("address", "");
            n.port = vn.optInt("port", 443);
            JSONArray users = vn.optJSONArray("users");
            if (users != null && users.length() > 0) {
                JSONObject u = users.optJSONObject(0);
                n.uuid = u.optString("id", "");
                n.flow = u.optString("flow", "");
                n.alterId = u.optInt("alterId", 0);
                n.vmessScy = u.optString("security", "auto");
                n.vmessPcs = u.optString("packetEncoding", "");
            }
            return n;
        }
        /* Xray 26 flat outbound form: settings.address/id/port/security. */
        if (s == null || s.optString("address", "").length() == 0) return null;
        n.host = s.optString("address", "");
        n.port = s.optInt("port", 443);
        n.uuid = s.optString("id", "");
        n.alterId = s.optInt("alterId", 0);
        n.vmessScy = s.optString("security", "auto");
        n.vmessPcs = s.optString("packetEncoding", "");
        return n;
    }

    /** trojan / socks / http：servers + 可选 users。 */
    private static Node server(JSONObject o, JSONObject s, JSONObject ss) {
        Node n = new Node();
        n.type = o.optString("protocol", "");
        JSONArray v = s != null ? s.optJSONArray("servers") : null;
        if (v == null || v.length() == 0) return null;
        JSONObject sn = v.optJSONObject(0);
        n.host = sn.optString("address", "");
        n.port = sn.optInt("port", 443);
        n.password = sn.optString("password", "");
        JSONArray users = sn.optJSONArray("users");
        if (users != null && users.length() > 0) {
            JSONObject u = users.optJSONObject(0);
            n.user = u.optString("user", "");
            if (n.password.isEmpty()) n.password = u.optString("pass", "");
        }
        return n;
    }

    /** shadowsocks 比 server 多一个 method，且内部类型统一成 "ss"。 */
    private static Node shadowsocks(JSONObject o, JSONObject s, JSONObject ss) {
        Node n = server(o, s, ss);
        if (n == null) return null;
        JSONArray v = s.optJSONArray("servers");
        n.method = v.optJSONObject(0).optString("method", "aes-256-gcm");
        n.type = Node.SS;
        return n;
    }

    private static Rule fromRoutingRule(JSONObject r) {
        String out = r.optString("outboundTag", "proxy");
        String action = out.equals("direct") ? Rule.A_DIRECT : (out.equals("block") ? Rule.A_BLOCK : Rule.A_PROXY);
        String[][] fields = {
                {"domain", Rule.F_DOMAIN}, {"domainSuffix", Rule.F_DOMAIN_SUFFIX},
                {"domainKeyword", Rule.F_DOMAIN_KEYWORD}, {"domainRegex", Rule.F_DOMAIN_REGEX},
                {"geosite", Rule.F_GEOSITE}, {"ip", Rule.F_IP}, {"geoip", Rule.F_GEOIP},
                {"port", Rule.F_PORT}, {"process", Rule.F_PROCESS}, {"inboundTag", Rule.F_INBOUND},
                {"network", Rule.F_NETWORK}};
        for (String[] f : fields) {
            JSONArray a = r.optJSONArray(f[0]);
            if (a != null && a.length() > 0) {
                Rule rule = new Rule(f[1], a.optString(0), action);
                return rule;
            }
        }
        return null;
    }

    /* ---------------- export ---------------- */

    public static String toLink(Node n) {
        try {
            if (Node.VMESS.equals(n.type)) {
                JSONObject o = new JSONObject();
                o.put("v", "2");
                o.put("ps", n.title());
                o.put("add", n.host);
                o.put("port", String.valueOf(n.port));
                o.put("id", n.uuid);
                o.put("aid", String.valueOf(n.alterId));
                o.put("net", n.net);
                o.put("type", n.headerType);
                o.put("host", n.hostHdr);
                o.put("path", n.path);
                o.put("tls", n.tls() ? "tls" : "");
                o.put("sni", n.sni);
                o.put("scy", n.vmessScy == null || n.vmessScy.length() == 0 ? "auto" : n.vmessScy);
                o.put("pcs", n.vmessPcs == null ? "" : n.vmessPcs);
                o.put("alpn", n.alpn == null ? "" : n.alpn);
                o.put("fp", n.fp == null ? "" : n.fp);
                o.put("insecure", n.allowInsecure ? "1" : "0");
                String json = o.toString().replace("\\/", "/");
                return "vmess://" + Base64.encodeToString(json.getBytes("UTF-8"),
                        Base64.NO_WRAP | Base64.URL_SAFE);
            }
            if (Node.SS.equals(n.type)) {
                String cred = Base64.encodeToString((n.method + ":" + n.password).getBytes("UTF-8"),
                        Base64.NO_WRAP | Base64.URL_SAFE);
                return "ss://" + cred + "@" + n.host + ":" + n.port + "#" + enc(n.title());
            }
            if (Node.SOCKS.equals(n.type) || Node.HTTP.equals(n.type)) {
                String cred = n.user.length() > 0
                        ? enc(n.user) + ":" + enc(n.password) + "@" : "";
                return n.type + "://" + cred + n.host + ":" + n.port + "#" + enc(n.title());
            }
            StringBuilder q = new StringBuilder();
            if (Node.VLESS.equals(n.type)) {
                q.append("type=").append(n.net);
                if (!n.path.isEmpty()) q.append("&path=").append(enc(n.path));
                if (!n.hostHdr.isEmpty()) q.append("&host=").append(enc(n.hostHdr));
                if (!n.serviceName.isEmpty()) q.append("&serviceName=").append(enc(n.serviceName));
                q.append("&security=").append(n.security);
                if (!n.sni.isEmpty()) q.append("&sni=").append(enc(n.sni));
                if (!n.fp.isEmpty()) q.append("&fp=").append(enc(n.fp));
                if (!n.flow.isEmpty()) q.append("&flow=").append(enc(n.flow));
                if (!n.pbk.isEmpty()) q.append("&pbk=").append(enc(n.pbk));
                if (!n.sid.isEmpty()) q.append("&sid=").append(enc(n.sid));
                if (n.allowInsecure) q.append("&allowInsecure=1");
                return "vless://" + enc(n.uuid) + "@" + n.host + ":" + n.port + "?" + q + "#" + enc(n.title());
            }
            if (Node.TROJAN.equals(n.type)) {
                q.append("type=").append(n.net);
                if (!n.path.isEmpty()) q.append("&path=").append(enc(n.path));
                if (!n.hostHdr.isEmpty()) q.append("&host=").append(enc(n.hostHdr));
                if (!n.sni.isEmpty()) q.append("&sni=").append(enc(n.sni));
                if (!n.fp.isEmpty()) q.append("&fp=").append(enc(n.fp));
                return "trojan://" + enc(n.password) + "@" + n.host + ":" + n.port + "?" + q + "#" + enc(n.title());
            }
        } catch (Exception ignored) {
        }
        return "";
    }

    /* ---------------- helpers ---------------- */

    private static String b64(String s) {
        String t = s.replace(' ', '+');
        int pad = t.length() % 4;
        if (pad == 2) t += "==";
        else if (pad == 3) t += "=";
        else if (pad == 1) t = t.substring(0, t.length() - 1);
        try {
            return new String(Base64.decode(t, Base64.NO_WRAP | Base64.URL_SAFE), "UTF-8");
        } catch (Exception e) {
            return new String(Base64.decode(t, Base64.NO_WRAP), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private static String enc(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            return s;
        }
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static int parseInt(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static Map<String, String> queryMap(String q) {
        Map<String, String> m = new HashMap<String, String>();
        if (q == null || q.isEmpty()) return m;
        for (String kv : q.split("&")) {
            int e = kv.indexOf('=');
            if (e > 0) m.put(kv.substring(0, e), urlDecode(kv.substring(e + 1)));
            else if (e < 0 && kv.length() > 0) m.put(kv, "");
        }
        return m;
    }

    private static String opt(Map<String, String> m, String k, String def) {
        String v = m.get(k);
        return v == null || v.length() == 0 ? def : v;
    }
}

