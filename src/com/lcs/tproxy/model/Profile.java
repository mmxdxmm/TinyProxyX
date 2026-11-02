package com.lcs.tproxy.model;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** A complete connection definition: an ordered hop chain plus routing policy. */
public class Profile {
    public static final String P_GLOBAL = "global";
    public static final String P_BYPASS_CN = "bypass_cn";
    public static final String P_BYPASS_LAN = "bypass_lan";
    public static final String P_NONE = "none";

    /** IPv6 策略：接管后直送链路 / 接管后丢黑洞 / 完全不接管（会漏真实地址） */
    public static final String V6_PROXY = "proxy";
    public static final String V6_BLOCK = "block";
    public static final String V6_DIRECT = "direct";

    /** 三态策略：禁用 / 代理 / 直连。默认全部采用不放行的值。 */
    public static final String UDP_BLOCK = "block";
    public static final String UDP_PROXY = "proxy";
    public static final String UDP_DIRECT = "direct";
    public static final String DNS_BLOCK = "block";
    public static final String DNS_PROXY = "proxy";
    public static final String DNS_DIRECT = "direct";

    public String id = UUID.randomUUID().toString();
    public String name = "新配置";
    /** traffic order: index 0 is nearest the device */
    public List<Node> chain = new ArrayList<Node>();
    public List<Rule> rules = new ArrayList<Rule>();
    public String preset = P_GLOBAL;
    public boolean mux = false;
    public boolean sniff = true;
    public boolean fragment = false;
    public String logLevel = "warning";
    public String dnsRemote = "";
    public String dnsDirect = "";
    public boolean overrideDns = false;
    public boolean perAppEnabled = false;
    public boolean perAppAllowMode = false;
    /** IPv6 策略，见下面三个常量。默认直送链路 —— 落地机有 v6 时，图片/直播那些 v6 分片才走得通 */
    public String v6 = V6_PROXY;
    /** 非 DNS UDP；block 默认，绝不隐式直连。 */
    public String udpPolicy = UDP_BLOCK;
    /** QUIC 443 单独控制，优先于通用 UDP。 */
    public String quicPolicy = UDP_BLOCK;
    /** 应用 DNS（53）策略；默认代理，不是直连。 */
    public String dnsPolicy = DNS_PROXY;
    /** Full xray/v2ray JSON imported as-is; non-empty means run the raw config. */
    public String rawJson = "";
    /** HTTP 注入首跳不能承载 UDP：proxy 必须降级为 block，不能降级为 direct。 */
    public boolean injectLead() {
        return !chain.isEmpty() && Node.INJECT.equals(chain.get(0).type);
    }

    /** 单节点注入配置里选中的 UDP 承载节点；链式配置一律返回 null，避免和链路语义打架。 */
    public Node udpSplit() {
        if (chain.size() != 1) return null;
        Node head = chain.get(0);
        if (!Node.INJECT.equals(head.type) || head.udpNode == null) return null;
        Node u = head.udpNode;
        if (!Node.udpCapable(u.type)) return null;
        if (u.host == null || u.host.trim().length() == 0 || u.port <= 0) return null;
        return u;
    }

    public boolean udpSplitViaInject() {
        return chain.size() == 1 && chain.get(0).udpNode != null && chain.get(0).udpViaInject;
    }
    /* 三个策略都只存字符串，但取值只有 block/proxy/direct：一次查表归一，
     * 不再让每条规则、每次建配置都跑一遍字符串比较链。 */
    public String effectiveUdpPolicy() {
        return Kinds.POLICY[Kinds.policy(udpPolicy, Kinds.POL_BLOCK)];
    }
    public String effectiveQuicPolicy() {
        return Kinds.POLICY[Kinds.policy(quicPolicy, Kinds.POL_BLOCK)];
    }
    public String effectiveDnsPolicy() {
        return Kinds.POLICY[Kinds.policy(dnsPolicy, Kinds.POL_PROXY)];
    }
    /** 接管（抓进隧道）：proxy / block 都要抓；direct 就是不抓，v6 直接走系统网络 */
    public boolean captureV6() {
        return !V6_DIRECT.equals(v6);
    }
    public boolean blockV6() {
        return V6_BLOCK.equals(v6);
    }
    public List<String> apps = new ArrayList<String>();
    public int updated = 0;

    public Profile() {
    }

    public Profile(String name) {
        this.name = name;
    }

    public Node exit() {
        return chain.isEmpty() ? null : chain.get(chain.size() - 1);
    }

    public Node entry() {
        return chain.isEmpty() ? null : chain.get(0);
    }

    public String chainSummary() {
        if (chain.isEmpty()) return "空链路";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < chain.size(); i++) {
            if (i > 0) sb.append(" → ");
            Node n = chain.get(i);
            sb.append(n.name != null && n.name.length() > 0 ? n.name : n.type.toUpperCase());
        }
        return sb.toString();
    }

    /** card subtitle: one hop = its address, many hops = the whole path */
    public String desc() {
        if (chain.isEmpty()) return "未配置服务器";
        if (chain.size() == 1) return exit().summary();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < chain.size(); i++) {
            if (i > 0) sb.append(" → ");
            Node n = chain.get(i);
            sb.append(n.host.length() > 0 ? n.host : n.type.toUpperCase());
        }
        return sb.append("（").append(chain.size()).append(" 跳）").toString();
    }

    /** deep copy that keeps id and name, used as the editing buffer */
    public Profile draft() {
        Profile p = new Profile(name);
        p.id = id;
        for (Node n : chain) p.chain.add(n.copy());
        for (Rule r : rules) p.rules.add(r.copy());
        p.preset = preset;
        p.mux = mux;
        p.sniff = sniff;
        p.fragment = fragment;
        p.logLevel = logLevel;
        p.dnsRemote = dnsRemote;
        p.dnsDirect = dnsDirect;
        p.overrideDns = overrideDns;
        p.perAppEnabled = perAppEnabled;
        p.perAppAllowMode = perAppAllowMode;
        p.v6 = v6;
        p.udpPolicy = udpPolicy;
        p.quicPolicy = quicPolicy;
        p.dnsPolicy = dnsPolicy;
        p.rawJson = rawJson;
        p.apps = new ArrayList<String>(apps);
        p.updated = updated;
        return p;
    }

    /** copy every editable field of {@code src} into this instance, keeping the identity */
    public void takeFrom(Profile src) {
        name = src.name;
        chain = src.chain;
        rules = src.rules;
        preset = src.preset;
        mux = src.mux;
        sniff = src.sniff;
        fragment = src.fragment;
        logLevel = src.logLevel;
        dnsRemote = src.dnsRemote;
        dnsDirect = src.dnsDirect;
        overrideDns = src.overrideDns;
        perAppEnabled = src.perAppEnabled;
        perAppAllowMode = src.perAppAllowMode;
        v6 = src.v6;
        udpPolicy = src.udpPolicy;
        quicPolicy = src.quicPolicy;
        dnsPolicy = src.dnsPolicy;
        rawJson = src.rawJson;
        apps = src.apps;
    }

    public Profile copy() {
        Profile p = new Profile(name + " 副本");
        p.id = UUID.randomUUID().toString();
        for (Node n : chain) p.chain.add(n.copy());
        for (Rule r : rules) p.rules.add(r.copy());
        p.preset = preset;
        p.mux = mux;
        p.sniff = sniff;
        p.fragment = fragment;
        p.logLevel = logLevel;
        p.dnsRemote = dnsRemote;
        p.dnsDirect = dnsDirect;
        p.overrideDns = overrideDns;
        p.perAppEnabled = perAppEnabled;
        p.perAppAllowMode = perAppAllowMode;
        p.v6 = v6;
        p.udpPolicy = udpPolicy;
        p.quicPolicy = quicPolicy;
        p.dnsPolicy = dnsPolicy;
        p.rawJson = rawJson;
        p.apps = new ArrayList<String>(apps);
        return p;
    }

    public JSONObject toJson() {
        JSONObject o = new JSONObject();
        try {
            o.put("id", id);
            o.put("name", name);
            JSONArray a = new JSONArray();
            for (Node n : chain) a.put(n.toJson());
            o.put("chain", a);
            JSONArray r = new JSONArray();
            for (Rule x : rules) r.put(x.toJson());
            o.put("rules", r);
            o.put("preset", preset);
            o.put("mux", mux);
            o.put("sniff", sniff);
            o.put("fragment", fragment);
            o.put("logLevel", logLevel);
            o.put("dnsRemote", dnsRemote);
            o.put("dnsDirect", dnsDirect);
            o.put("overrideDns", overrideDns);
            o.put("perAppEnabled", perAppEnabled);
            o.put("perAppAllowMode", perAppAllowMode);
            o.put("v6", v6);
            o.put("udpPolicy", udpPolicy);
            o.put("quicPolicy", quicPolicy);
            o.put("dnsPolicy", dnsPolicy);
            o.put("rawJson", rawJson);
            o.put("apps", new JSONArray(apps));
            o.put("updated", updated);
        } catch (Exception ignored) {
        }
        return o;
    }

    private static String policy(String v, String def) {
        int defId = Kinds.policy(def, Kinds.POL_BLOCK);
        return Kinds.POLICY[Kinds.policy(v, defId)];
    }

    public static Profile fromJson(JSONObject o) {
        Profile p = new Profile();
        p.id = o.optString("id", UUID.randomUUID().toString());
        p.name = o.optString("name", "配置");
        JSONArray a = o.optJSONArray("chain");
        if (a != null) {
            for (int i = 0; i < a.length(); i++) {
                JSONObject hop = a.optJSONObject(i);
                if (hop == null) continue;
                /* 1.8.2 移除了 gost 引擎。旧存档里的 gost 跳直接跳过，
                 * 不让它进入链路，后续构建 xray 配置时就不会再撞到未知协议。 */
                if ("gost".equals(hop.optString("type", ""))) continue;
                p.chain.add(Node.fromJson(hop));
            }
        }
        JSONArray r = o.optJSONArray("rules");
        if (r != null) for (int i = 0; i < r.length(); i++) p.rules.add(Rule.fromJson(r.optJSONObject(i)));
        p.preset = o.optString("preset", P_GLOBAL);
        p.mux = o.optBoolean("mux", false);
        p.sniff = o.optBoolean("sniff", true);
        p.fragment = o.optBoolean("fragment", false);
        p.logLevel = o.optString("logLevel", "warning");
        p.dnsRemote = o.optString("dnsRemote", "");
        p.dnsDirect = o.optString("dnsDirect", "");
        p.overrideDns = o.optBoolean("overrideDns", false);
        p.perAppEnabled = o.optBoolean("perAppEnabled", false);
        p.perAppAllowMode = o.optBoolean("perAppAllowMode", false);
        p.v6 = o.optString("v6", "");
        if (p.v6.length() == 0) {
            /* 老存档只有 blockIpv6 一个开关。true 曾经是默认值，也正是它把 v6-only 的应用
             * （图片 CDN / 直播）打死过 —— 老数据一律迁到「直送链路」，
             * 想要丢黑洞得自己在路由页明确选一次。 */
            p.v6 = V6_PROXY;
        }
        p.udpPolicy = policy(o.optString("udpPolicy", UDP_BLOCK), UDP_BLOCK);
        p.quicPolicy = policy(o.optString("quicPolicy", UDP_BLOCK), UDP_BLOCK);
        p.dnsPolicy = policy(o.optString("dnsPolicy", DNS_PROXY), DNS_PROXY);
        p.rawJson = o.optString("rawJson", "");
        JSONArray apps = o.optJSONArray("apps");
        if (apps != null) for (int i = 0; i < apps.length(); i++) p.apps.add(apps.optString(i));
        p.updated = o.optInt("updated", 0);
        return p;
    }
}
