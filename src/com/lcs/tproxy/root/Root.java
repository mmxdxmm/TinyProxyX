package com.lcs.tproxy.root;

import android.content.Context;

import com.lcs.tproxy.core.Bin;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;

import java.io.File;
import java.io.FileOutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Root steering. Every traffic class is explicit: block, proxy or direct. */
public class Root {
    public static final int FW_MARK = 1;
    /** xray's own sockets carry this mark and bypass the local capture chains. */
    public static final int XRAY_MARK = 255;
    public static final int TABLE = 100;
    public static final int RULE_PREF = 100;
    private static final String UPLINK_SH =
            "UP=$(ip route show default 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p' | head -n1)\n"
                    + "UP6=$(ip -6 route show default 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p' | sort -u)\n";
    public static final String CH_LOCAL = "TP_LOCAL";
    public static final String CH_PRE = "TP_PRE";
    public static final String CH_UDP = "TP_UDP";
    public static final String CH_FORWARD_UDP = "TP_FORWARD_UDP";
    public static final String CH_LOOP = "TP_LOOP";
    public static final String CH6_LOCAL = "TP6_LOCAL";
    public static final String CH6_PRE = "TP6_PRE";
    public static final String CH6_UDP = "TP6_UDP";
    public static final String CH6_LOOP = "TP6_LOOP";
    /** v6 策略是「丢弃」时 filter 表的兜底链：不依赖 mangle 那条规则是否真的生效 */
    private static final String CH6_FWD = "TP6_FWD";
    private static final String[] CHAINS = {CH_LOCAL, CH_PRE, CH_UDP, CH_FORWARD_UDP, CH_LOOP,
            CH6_LOCAL, CH6_PRE, CH6_UDP, CH6_LOOP};
    private static final String V4_LINK = "169.254.0.0/16";
    private static final String[] V4_PRIVATE = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", V4_LINK};
    private static final String[] V4_NEVER = {"127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"};
    private static final String[] V6_NEVER = {"::1/128", "fe80::/10", "ff02::/16", "ff00::/8"};

    public static class Iface {
        public String name;
        public boolean up;
        public String addr;
        public boolean hotspot;
    }

    public static boolean hasRoot() {
        String out = Bin.runAndRead("su", "-c", "id");
        return out != null && out.contains("uid=0");
    }

    public static List<Iface> interfaces() {
        List<Iface> list = new ArrayList<Iface>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (ni.getName().equals("lo")) continue;
                Iface f = new Iface();
                f.name = ni.getName();
                f.up = ni.isUp();
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address) {
                        f.addr = a.getHostAddress();
                        break;
                    }
                }
                f.hotspot = guessHotspot(ni.getName());
                list.add(f);
            }
        } catch (Exception ignored) {
        }
        Collections.sort(list, new java.util.Comparator<Iface>() {
            public int compare(Iface a, Iface b) { return a.name.compareTo(b.name); }
        });
        return list;
    }

    public static boolean guessHotspot(String n) {
        String s = n.toLowerCase();
        return s.startsWith("ap") || s.contains("softap") || s.contains("swlan")
                || s.startsWith("wlan1") || s.startsWith("br") || s.contains("rndis")
                || s.startsWith("usb") || s.startsWith("eth") || s.contains("wifi-direct") || s.startsWith("p2p");
    }

    public static List<String> hotspotIfaces() {
        List<String> out = new ArrayList<String>();
        for (Iface f : interfaces()) if (f.hotspot && f.up) out.add(f.name);
        return out;
    }

    public static List<String> effectiveIfs(Store.Settings s) {
        List<String> picked = new ArrayList<String>();
        for (String p : s.proxyIfs) if (p != null && p.length() > 0 && !picked.contains(p)) picked.add(p);
        boolean all = picked.isEmpty() || picked.contains("*");
        if (all) { picked.clear(); picked.add("*"); }
        if (s.rootHotspot) {
            for (String h : hotspotIfaces()) {
                if (!picked.contains(h)) {
                    if (all) break;
                    picked.add(h);
                }
            }
        }
        return picked;
    }

    public static boolean isAll(List<String> proxyIfs) { return proxyIfs.contains("*"); }

    /** Legacy preview entry point: conservative defaults, never implicit direct. */
    public static String script(Context c, Store.Settings s, int redirectPort, int tproxyPort, int uid, String v6) {
        return script(c, s, effectiveIfs(s), redirectPort, tproxyPort, uid, v6);
    }

    public static String script(Context c, Store.Settings s, List<String> proxyIfs,
                                int redirectPort, int tproxyPort, int uid, String v6) {
        return script(c, s, proxyIfs, redirectPort, tproxyPort, uid, v6, null);
    }

    /** Main entry: all policies come from the selected profile. */
    public static String script(Context c, Store.Settings s, List<String> proxyIfs,
                                int redirectPort, int tproxyPort, int uid, String v6, Profile p) {
        String udp = p == null ? (s.rootUdp ? Profile.UDP_PROXY : Profile.UDP_BLOCK) : p.effectiveUdpPolicy();
        String quic = p == null ? udp : p.effectiveQuicPolicy();
        String dns = p == null ? (s.dnsHijack ? Profile.DNS_PROXY : Profile.DNS_BLOCK) : p.effectiveDnsPolicy();
        boolean blockV6 = Profile.V6_BLOCK.equals(v6);
        boolean directV6 = Profile.V6_DIRECT.equals(v6);
        boolean proxyV6 = Profile.V6_PROXY.equals(v6);
        boolean local = s.rootProxyLocal;
        boolean forward = s.rootHotspot;
        boolean proxyUdp = proxy(udp) || proxy(quic) || proxy(dns);
        boolean needV6 = !directV6 && (local || forward);
        boolean needRoute4 = (local || forward) && proxyUdp;
        boolean needRoute6 = needV6 && (proxyV6 || proxy(dns));

        StringBuilder b = new StringBuilder();
        b.append("#!/system/bin/sh\nset +e\n");
        b.append("FAILED=0\nrun() { \"$@\" || FAILED=1; }\n");
        b.append("UID_APP=").append(uid).append("\nRDPORT=").append(redirectPort)
                .append("\nTPPORT=").append(tproxyPort).append("\n");
        reset(b);
        if (needRoute4) route(b, "ip", "0.0.0.0/0");
        if (needRoute6) route(b, "ip -6", "::/0");
        b.append(UPLINK_SH);

        if (local) {
            localV4(b, s, dns);
            localUdpV4(b, s, udp, quic, dns);
            if (proxyUdp) loopV4(b);
        }
        if (forward) {
            forwardV4(b, s, proxyIfs, dns);
            forwardUdpV4(b, s, proxyIfs, dns, udp, quic);
        }
        if (needV6) {
            if (local) {
                localV6(b, s, blockV6, proxyV6, dns, udp, quic);
                if (proxyV6 || proxy(dns)) loopV6(b);
            }
            if (forward) forwardV6(b, s, proxyIfs, blockV6, proxyV6, dns, udp, quic);
        }
        if (needV6 && forward && blockV6) {
            /* filter 表兜底：v6 策略是「丢弃」时，转发链直接 DROP。
             * mangle 里那条 -j DROP 依赖 PREROUTING 被走到；有的 ROM 会绕过，
             * 热点设备就能拿到公网 v6 直接出去 —— 那才是真的 IP 泄露。 */
            b.append("run ip6tables -w -t filter -N ").append(CH6_FWD).append("\n");
            b.append("run ip6tables -w -t filter -A ").append(CH6_FWD).append(" -j DROP\n");
            b.append("run ip6tables -w -t filter -I FORWARD -j ").append(CH6_FWD).append("\n");
        }
        if (local || forward) verify(b, local, forward, needV6, proxyV6, proxy(dns),
                proxyUdp, needRoute4, needRoute6);
        b.append("[ \"$FAILED\" -eq 0 ] && echo ROOT_APPLIED\n");
        b.append("[ \"$FAILED\" -ne 0 ] && echo ROOT_RULE_FAILED\n");
        return b.toString();
    }

    private static boolean proxy(String p) { return Profile.UDP_PROXY.equals(p); }
    private static boolean direct(String p) { return Profile.UDP_DIRECT.equals(p); }
    private static boolean block(String p) { return Profile.UDP_BLOCK.equals(p); }

    private static void route(StringBuilder b, String ip, String net) {
        b.append("run ").append(ip).append(" rule add fwmark ").append(FW_MARK)
                .append(" lookup ").append(TABLE).append(" pref ").append(RULE_PREF).append("\n");
        b.append(ip).append(" route flush table ").append(TABLE).append(" 2>/dev/null\n");
        b.append("run ").append(ip).append(" route add local ").append(net)
                .append(" dev lo table ").append(TABLE).append("\n");
    }

    /* ------------------------------------------------------------ local IPv4 */

    private static void localV4(StringBuilder b, Store.Settings s, String dns) {
        b.append("run iptables -w -t nat -N ").append(CH_LOCAL).append("\n");
        ret(b, CH_LOCAL, "-m mark --mark " + XRAY_MARK + "/0xffffffff");
        dnsLocalTcp(b, CH_LOCAL, dns);
        ret(b, CH_LOCAL, "-m owner --uid-owner $UID_APP");
        ret(b, CH_LOCAL, "-m owner --uid-owner 0");
        ret(b, CH_LOCAL, "-p tcp --dport $RDPORT");
        ret(b, CH_LOCAL, "-p tcp --dport $TPPORT");
        for (String n : V4_NEVER) ret(b, CH_LOCAL, "-d " + n);
        for (String i : s.bypassIfs) ret(b, CH_LOCAL, "-o " + i);
        if (s.bypassPrivate) for (String n : V4_PRIVATE) ret(b, CH_LOCAL, "-d " + n);
        redirect(b, CH_LOCAL, "");
        hook(b, "iptables -w -t nat", "OUTPUT", CH_LOCAL);
    }

    private static void localUdpV4(StringBuilder b, Store.Settings s, String udp, String quic, String dns) {
        b.append("run iptables -w -t mangle -N ").append(CH_UDP).append("\n");
        ret(b, CH_UDP, "-m mark --mark " + XRAY_MARK + "/0xffffffff");
        udpLocal(b, CH_UDP, "-p udp --dport 53", dns);
        ret(b, CH_UDP, "-m owner --uid-owner $UID_APP");
        ret(b, CH_UDP, "-m owner --uid-owner 0");
        for (String n : V4_NEVER) ret(b, CH_UDP, "-d " + n);
        for (String i : s.bypassIfs) ret(b, CH_UDP, "-o " + i);
        if (s.bypassPrivate) for (String n : V4_PRIVATE) ret(b, CH_UDP, "-d " + n);
        udpLocal(b, CH_UDP, "-p udp --dport 443", quic);
        udpLocal(b, CH_UDP, "-p udp", udp);
        hook(b, "iptables -w -t mangle", "OUTPUT", CH_UDP);
    }

    private static void loopV4(StringBuilder b) {
        b.append("run iptables -w -t mangle -N ").append(CH_LOOP).append("\n");
        tproxy(b, CH_LOOP, "-i lo -m mark --mark " + FW_MARK + "/0xffffffff -p udp");
        hook(b, "iptables -w -t mangle", "PREROUTING", CH_LOOP);
    }

    /* ---------------------------------------------------------- forwarded IPv4 */

    private static void forwardV4(StringBuilder b, Store.Settings s, List<String> ifs, String dns) {
        b.append("run iptables -w -t nat -N ").append(CH_PRE).append("\n");
        ret(b, CH_PRE, "-i lo");
        uplinkGuard(b, "iptables -w -t nat", CH_PRE);
        for (String n : V4_NEVER) ret(b, CH_PRE, "-d " + n);
        /* DNS is handled in mangle for both protocols; never let nat REDIRECT it. */
        ret(b, CH_PRE, "-p tcp --dport 53");
        ret(b, CH_PRE, "-p tcp --dport $RDPORT");
        for (String n : V4_PRIVATE) ret(b, CH_PRE, "-d " + n);
        for (String i : s.bypassIfs) ret(b, CH_PRE, "-i " + i);
        for (String i : ifs) if (!i.equals("*")) redirect(b, CH_PRE, "-i " + i);
        if (isAll(ifs)) redirect(b, CH_PRE, "");
        hook(b, "iptables -w -t nat", "PREROUTING", CH_PRE);
    }

    private static void forwardUdpV4(StringBuilder b, Store.Settings s, List<String> ifs,
                                     String dns, String udp, String quic) {
        b.append("run iptables -w -t mangle -N ").append(CH_FORWARD_UDP).append("\n");
        ret(b, CH_FORWARD_UDP, "-i lo");
        uplinkGuard(b, "iptables -w -t mangle", CH_FORWARD_UDP);
        for (String n : V4_NEVER) ret(b, CH_FORWARD_UDP, "-d " + n);
        dnsForward(b, CH_FORWARD_UDP, ifs, dns);
        for (String n : V4_PRIVATE) ret(b, CH_FORWARD_UDP, "-d " + n);
        for (String i : s.bypassIfs) ret(b, CH_FORWARD_UDP, "-i " + i);
        udpForward(b, CH_FORWARD_UDP, ifs, "-p udp --dport 443", quic);
        udpForward(b, CH_FORWARD_UDP, ifs, "-p udp", udp);
        hook(b, "iptables -w -t mangle", "PREROUTING", CH_FORWARD_UDP);
        b.append("run sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'\n");
    }

    /* ------------------------------------------------------------------- IPv6 */

    private static void localV6(StringBuilder b, Store.Settings s, boolean blockV6, boolean proxyV6,
                                String dns, String udp, String quic) {
        b.append("run ip6tables -w -t mangle -N ").append(CH6_LOCAL).append("\n");
        ret(b, CH6_LOCAL, "-m mark --mark " + XRAY_MARK + "/0xffffffff");
        dnsLocalV6(b, CH6_LOCAL, dns);
        ret(b, CH6_LOCAL, "-m owner --uid-owner $UID_APP");
        ret(b, CH6_LOCAL, "-m owner --uid-owner 0");
        for (String n : V6_NEVER) ret(b, CH6_LOCAL, "-d " + n);
        for (String i : s.bypassIfs) ret(b, CH6_LOCAL, "-o " + i);
        if (s.bypassPrivate) ret(b, CH6_LOCAL, "-d fc00::/7");
        if (blockV6) {
            drop(b, CH6_LOCAL, "");
        } else if (proxyV6) {
            udpLocal(b, CH6_LOCAL, "-p udp --dport 443", quic);
            udpLocal(b, CH6_LOCAL, "-p udp", udp);
            mark(b, CH6_LOCAL, "-p tcp");
        }
        hook(b, "ip6tables -w -t mangle", "OUTPUT", CH6_LOCAL);
    }

    private static void loopV6(StringBuilder b) {
        b.append("run ip6tables -w -t mangle -N ").append(CH6_LOOP).append("\n");
        tproxy(b, CH6_LOOP, "-i lo -m mark --mark " + FW_MARK + "/0xffffffff -p tcp");
        tproxy(b, CH6_LOOP, "-i lo -m mark --mark " + FW_MARK + "/0xffffffff -p udp");
        hook(b, "ip6tables -w -t mangle", "PREROUTING", CH6_LOOP);
    }

    private static void forwardV6(StringBuilder b, Store.Settings s, List<String> ifs,
                                  boolean blockV6, boolean proxyV6, String dns, String udp, String quic) {
        b.append("run ip6tables -w -t mangle -N ").append(CH6_PRE).append("\n");
        ret(b, CH6_PRE, "-i lo");
        uplinkGuard(b, "ip6tables -w -t mangle", CH6_PRE);
        for (String n : V6_NEVER) ret(b, CH6_PRE, "-d " + n);
        dnsForwardV6(b, CH6_PRE, ifs, dns);
        ret(b, CH6_PRE, "-d fc00::/7");
        for (String i : s.bypassIfs) ret(b, CH6_PRE, "-i " + i);
        if (blockV6) {
            drop(b, CH6_PRE, "");
        } else if (proxyV6) {
            udpForward(b, CH6_PRE, ifs, "-p udp --dport 443", quic);
            udpForward(b, CH6_PRE, ifs, "-p udp", udp);
            tcpForward(b, CH6_PRE, ifs);
        }
        hook(b, "ip6tables -w -t mangle", "PREROUTING", CH6_PRE);
        b.append("run sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'\n");
    }

    /* --------------------------------------------------------------- policies */

    private static void dnsLocalTcp(StringBuilder b, String chain, String policy) {
        /* nat is not a filtering table: both proxy and block hand TCP DNS to
         * xray (redirect-in). xray's port-53 route then answers or blackholes it. */
        if (proxy(policy) || block(policy)) redirect(b, chain, "--dport 53");
        else ret(b, chain, "-p tcp --dport 53");
    }

    private static void dnsLocalV6(StringBuilder b, String chain, String policy) {
        for (String proto : new String[]{"tcp", "udp"}) {
            String match = "-p " + proto + " --dport 53";
            if (proxy(policy)) { mark(b, chain, match); ret(b, chain, match); }
            else if (block(policy)) drop(b, chain, match);
            else ret(b, chain, match);
        }
    }

    private static void dnsForward(StringBuilder b, String chain, List<String> ifs, String policy) {
        for (String i : ifs) {
            String pre = i.equals("*") ? "" : "-i " + i + " ";
            for (String proto : new String[]{"tcp", "udp"}) {
                String match = pre + "-p " + proto + " --dport 53";
                if (proxy(policy)) tproxy(b, chain, match);
                else if (block(policy)) drop(b, chain, match);
                else ret(b, chain, match);
            }
        }
    }

    private static void dnsForwardV6(StringBuilder b, String chain, List<String> ifs, String policy) {
        dnsForward(b, chain, ifs, policy);
    }

    /** Local UDP policy: proxy uses mark+return, block drops, direct returns. */
    private static void udpLocal(StringBuilder b, String chain, String match, String policy) {
        if (proxy(policy)) { mark(b, chain, match); ret(b, chain, match); }
        else if (block(policy)) drop(b, chain, match);
        else ret(b, chain, match);
    }

    /** Forward UDP policy: proxy uses TPROXY, block drops, direct returns. */
    private static void udpForward(StringBuilder b, String chain, List<String> ifs, String match, String policy) {
        for (String i : ifs) {
            String m = (i.equals("*") ? "" : "-i " + i + " ") + match;
            if (proxy(policy)) tproxy(b, chain, m);
            else if (block(policy)) drop(b, chain, m);
            else ret(b, chain, m);
        }
    }

    private static void tcpForward(StringBuilder b, String chain, List<String> ifs) {
        for (String i : ifs) {
            String m = (i.equals("*") ? "" : "-i " + i + " ") + "-p tcp";
            tproxy(b, chain, m);
        }
    }

    /* ------------------------------------------------------------------- utils */

    private static String cmd(String chain) {
        if (chain.startsWith("TP6")) return "ip6tables -w -t mangle";
        return chain.equals(CH_UDP) || chain.equals(CH_FORWARD_UDP) || chain.equals(CH_LOOP)
                ? "iptables -w -t mangle" : "iptables -w -t nat";
    }

    /** 上行网卡的 RETURN。v4 / v6 的默认路由可能不在同一张网卡上（Wi-Fi 跑 v6、蜂窝跑 v4
     *  这种组合很常见），只豁免 v4 那张的话，v6 回来的包会被当成"转发的流量"劫进 xray：
     *  节点是 v6-only 时，VMess 的 SYN-ACK 被 TPROXY 吃掉，DoH 两秒后 closed pipe。 */
    private static void uplinkGuard(StringBuilder b, String table, String chain) {
        b.append("[ -z \"$UP\" ] || run ").append(table).append(" -A ").append(chain)
                .append(" -i \"$UP\" -j RETURN\n");
        b.append("for u in $UP6; do [ -n \"$u\" ] && run ").append(table).append(" -A ")
                .append(chain).append(" -i \"$u\" -j RETURN; done\n");
    }

    private static void ret(StringBuilder b, String chain, String cond) {
        b.append("run ").append(cmd(chain)).append(" -A ").append(chain).append(' ')
                .append(cond.trim()).append(" -j RETURN\n");
    }

    private static void redirect(StringBuilder b, String chain, String cond) {
        String c = cond.trim();
        b.append("run ").append(cmd(chain)).append(" -A ").append(chain).append(" -p tcp")
                .append(c.length() == 0 ? "" : " " + c).append(" -j REDIRECT --to-ports $RDPORT\n");
    }

    private static void tproxy(StringBuilder b, String chain, String cond) {
        b.append("run ").append(cmd(chain)).append(" -A ").append(chain).append(' ')
                .append(cond.trim()).append(" -j TPROXY --on-port $TPPORT --tproxy-mark ")
                .append(FW_MARK).append("\n");
    }

    private static void mark(StringBuilder b, String chain, String cond) {
        b.append("run ").append(cmd(chain)).append(" -A ").append(chain).append(' ')
                .append(cond.trim()).append(" -j MARK --set-mark ").append(FW_MARK).append("\n");
    }

    private static void drop(StringBuilder b, String chain, String cond) {
        String c = cond.trim();
        b.append("run ").append(cmd(chain)).append(" -A ").append(chain)
                .append(c.length() == 0 ? "" : " " + c).append(" -j DROP\n");
    }

    private static void hook(StringBuilder b, String command, String where, String chain) {
        b.append("run ").append(command).append(" -A ").append(where).append(" -j ").append(chain).append("\n");
    }

    private static void verify(StringBuilder b, boolean local, boolean forward, boolean needV6,
                               boolean proxyV6, boolean dnsProxy, boolean proxyUdp,
                               boolean route4, boolean route6) {
        if (local) {
            b.append("iptables -w -t nat -C OUTPUT -j ").append(CH_LOCAL).append(" || FAILED=1\n");
            b.append("iptables -w -t mangle -C OUTPUT -j ").append(CH_UDP).append(" || FAILED=1\n");
            if (proxyUdp) b.append("iptables -w -t mangle -C PREROUTING -j ").append(CH_LOOP).append(" || FAILED=1\n");
        }
        if (forward) {
            b.append("iptables -w -t nat -C PREROUTING -j ").append(CH_PRE).append(" || FAILED=1\n");
            b.append("iptables -w -t mangle -C PREROUTING -j ").append(CH_FORWARD_UDP).append(" || FAILED=1\n");
        }
        if (route4) {
            b.append("ip rule show | grep -q 'fwmark 0x1.*lookup 100' || FAILED=1\n");
            b.append("ip route show table 100 | grep -q 'local default dev lo' || FAILED=1\n");
        }
        if (needV6 && local) {
            b.append("ip6tables -t mangle -C OUTPUT -j ").append(CH6_LOCAL).append(" || FAILED=1\n");
            if (proxyV6 || dnsProxy) b.append("ip6tables -t mangle -C PREROUTING -j ").append(CH6_LOOP).append(" || FAILED=1\n");
        }
        if (needV6 && forward) {
            b.append("ip6tables -t mangle -C PREROUTING -j ").append(CH6_PRE).append(" || FAILED=1\n");
        }
        if (route6) {
            b.append("ip -6 rule show | grep -q 'fwmark 0x1.*lookup 100' || FAILED=1\n");
            b.append("ip -6 route show table 100 | grep -q 'local default dev lo' || FAILED=1\n");
        }
    }

    private static void reset(StringBuilder b) {
        for (String c : CHAINS) {
            String fam = c.startsWith("TP6") ? "ip6tables -w" : "iptables -w";
            for (String t : new String[]{"nat", "mangle"}) {
                for (String h : new String[]{"OUTPUT", "PREROUTING"}) {
                    b.append(fam).append(" -t ").append(t).append(" -D ").append(h)
                            .append(" -j ").append(c).append(" 2>/dev/null\n");
                }
                b.append(fam).append(" -t ").append(t).append(" -F ").append(c).append(" 2>/dev/null\n");
                b.append(fam).append(" -t ").append(t).append(" -X ").append(c).append(" 2>/dev/null\n");
            }
        }
        for (String r : new String[]{"ip rule", "ip -6 rule"}) {
            b.append("while ").append(r).append(" del fwmark ").append(FW_MARK)
                    .append(" lookup ").append(TABLE).append(" 2>/dev/null; do :; done\n");
            b.append("while ").append(r).append(" del fwmark ").append(FW_MARK)
                    .append(" 2>/dev/null; do :; done\n");
        }
        b.append("ip route flush table ").append(TABLE).append(" 2>/dev/null\n");
        b.append("ip -6 route flush table ").append(TABLE).append(" 2>/dev/null\n");
        b.append("ip6tables -w -t filter -D FORWARD -j ").append(CH6_FWD).append(" 2>/dev/null\n");
        b.append("ip6tables -w -t filter -F ").append(CH6_FWD).append(" 2>/dev/null\n");
        b.append("ip6tables -w -t filter -X ").append(CH6_FWD).append(" 2>/dev/null\n");
    }

    public static String cleanupScript() {
        StringBuilder b = new StringBuilder();
        b.append("#!/system/bin/sh\nset +e\nCLEAN=1\n");
        reset(b);
        for (String c : CHAINS) {
            String fam = c.startsWith("TP6") ? "ip6tables -w" : "iptables -w";
            b.append(fam).append(" -t nat -S ").append(c).append(" 2>/dev/null | grep -q . && CLEAN=0\n");
            b.append(fam).append(" -t mangle -S ").append(c).append(" 2>/dev/null | grep -q . && CLEAN=0\n");
        }
        b.append("ip rule show | grep -q 'fwmark 0x1.*lookup 100' && CLEAN=0\n");
        b.append("ip -6 rule show | grep -q 'fwmark 0x1.*lookup 100' && CLEAN=0\n");
        b.append("ip6tables -w -t filter -S ").append(CH6_FWD).append(" 2>/dev/null | grep -q . && CLEAN=0\n");
        b.append("[ \"$CLEAN\" -eq 1 ] && echo ROOT_CLEANED || echo ROOT_CLEAN_FAILED\n");
        return b.toString();
    }

    public static volatile String lastWarn = "";
    private static long appliedGeneration;

    public static synchronized boolean owns(long generation) {
        return generation != 0 && appliedGeneration == generation;
    }

    public static synchronized boolean cleanupIfOwner(Context c, long generation) {
        if (generation == 0 || appliedGeneration != generation) return true;
        return cleanup(c);
    }

    public static String apply(Context c, String script) {
        return apply(c, script, 0);
    }

    public static synchronized String apply(Context c, String script, long generation) {
        File f = new File(c.getFilesDir(), "root.sh");
        try {
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(script.getBytes("UTF-8"));
            fos.flush();
            fos.close();
        } catch (Exception e) {
            return "写入脚本失败: " + e.getMessage();
        }
        String out = Bin.runAndRead(20000L, "su", "-c", "sh " + f.getAbsolutePath());
        if (out == null) out = "";
        if (out.contains("ROOT_APPLIED") && !out.contains("ROOT_RULE_FAILED")) {
            appliedGeneration = generation;
            return null;
        }
        File clean = new File(c.getFilesDir(), "clean.sh");
        try {
            FileOutputStream fos = new FileOutputStream(clean);
            fos.write(cleanupScript().getBytes("UTF-8"));
            fos.flush();
            fos.close();
            Bin.runAndRead(20000L, "su", "-c", "sh " + clean.getAbsolutePath());
        } catch (Exception ignored) {
        }
        return out.length() > 0 ? out : "root 执行失败或超时";
    }

    public static synchronized boolean cleanup(Context c) {
        appliedGeneration = 0;
        File f = new File(c.getFilesDir(), "clean.sh");
        try {
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(cleanupScript().getBytes("UTF-8"));
            fos.flush();
            fos.close();
            String out = Bin.runAndRead(20000L, "su", "-c", "sh " + f.getAbsolutePath());
            return out != null && out.contains("ROOT_CLEANED") && !out.contains("ROOT_CLEAN_FAILED");
        } catch (Exception e) {
            return false;
        }
    }

    public static Map<String, String> iptablesSnapshot() {
        Map<String, String> m = new HashMap<String, String>();
        m.put("local", Bin.runAndRead("su", "-c", "iptables -w -t nat -S " + CH_LOCAL));
        m.put("forward", Bin.runAndRead("su", "-c", "iptables -w -t nat -S " + CH_PRE));
        m.put("udp", Bin.runAndRead("su", "-c", "iptables -w -t mangle -S " + CH_UDP));
        m.put("rule", Bin.runAndRead("su", "-c", "ip rule show"));
        return m;
    }
}
