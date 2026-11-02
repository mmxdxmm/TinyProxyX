package com.lcs.tproxy.model;

import org.json.JSONObject;

/** One routing rule, v2ray/xray shaped. */
public class Rule {
    public static final String F_DOMAIN = "domain";
    public static final String F_DOMAIN_SUFFIX = "domain_suffix";
    public static final String F_DOMAIN_KEYWORD = "domain_keyword";
    public static final String F_DOMAIN_REGEX = "domain_regex";
    public static final String F_GEOSITE = "geosite";
    public static final String F_IP = "ip";
    public static final String F_GEOIP = "geoip";
    public static final String F_PORT = "port";
    public static final String F_PROCESS = "process";
    public static final String F_INBOUND = "inbound";
    public static final String F_NETWORK = "network";

    public static final String A_PROXY = "proxy";
    public static final String A_DIRECT = "direct";
    public static final String A_BLOCK = "block";

    public String field = F_DOMAIN_SUFFIX;
    public String value = "";
    public String action = A_PROXY;
    public boolean invert = false;

    public Rule() {
    }

    public Rule(String field, String value, String action) {
        this.field = field;
        this.value = value;
        this.action = action;
    }

    public Rule copy() {
        Rule r = new Rule(field, value, action);
        r.invert = invert;
        return r;
    }

    public String label() {
        String f = fieldLabel(field);
        String a = A_DIRECT.equals(action) ? "直连" : A_BLOCK.equals(action) ? "拦截" : "代理";
        return (invert ? "!" : "") + f + " · " + value + " → " + a;
    }

    public static String fieldLabel(String f) {
        if (F_DOMAIN.equals(f)) return "域名";
        if (F_DOMAIN_SUFFIX.equals(f)) return "域名后缀";
        if (F_DOMAIN_KEYWORD.equals(f)) return "域名关键字";
        if (F_DOMAIN_REGEX.equals(f)) return "域名正则";
        if (F_GEOSITE.equals(f)) return "Geosite";
        if (F_IP.equals(f)) return "IP 段";
        if (F_GEOIP.equals(f)) return "GeoIP";
        if (F_PORT.equals(f)) return "端口";
        if (F_PROCESS.equals(f)) return "进程";
        if (F_INBOUND.equals(f)) return "入站";
        if (F_NETWORK.equals(f)) return "网络";
        return f;
    }

    public static String actionLabel(String a) {
        if (A_DIRECT.equals(a)) return "直连";
        if (A_BLOCK.equals(a)) return "拦截";
        return "代理";
    }

    public JSONObject toJson() {
        JSONObject o = new JSONObject();
        try {
            o.put("field", field);
            o.put("value", value);
            o.put("action", action);
            o.put("invert", invert);
        } catch (Exception ignored) {
        }
        return o;
    }

    public static Rule fromJson(JSONObject o) {
        Rule r = new Rule();
        r.field = o.optString("field", F_DOMAIN_SUFFIX);
        r.value = o.optString("value", "");
        r.action = o.optString("action", A_PROXY);
        r.invert = o.optBoolean("invert", false);
        return r;
    }
}
