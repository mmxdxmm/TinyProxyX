package com.lcs.tproxy.ui;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.lcs.tproxy.core.Control;
import com.lcs.tproxy.inject.Ini;
import com.lcs.tproxy.link.Links;
import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.xray.Conf;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The only editor in the app.
 *
 * <p>三种入口：
 * <ul>
 *   <li>新建配置（{@link #EXTRA_NEW}）——页面里默认「注入」，协议选框可以切成 vless/vmess/…
 *       或者「链路」，选链路就是多跳编辑；只有点保存才会进列表（草稿语义）。</li>
 *   <li>编辑已有配置（{@link #EXTRA_PROFILE}）——编辑的是深拷贝草稿，取消即丢弃。</li>
 *   <li>编辑单个节点（{@link #EXTRA_NODE}）——链路里某跳的回编，保存后把节点 JSON 回传给父页面。</li>
 * </ul>
 */
public class EditActivity extends Activity {

    public static final String EXTRA_PROFILE = "profile";
    public static final String EXTRA_NEW = "new";
    public static final String EXTRA_NODE = "node";
    public static final String EXTRA_NODE_JSON = "node_json";
    /** 这一跳是链式配置里的一跳：不提供 UDP 转换，避免和链路语义冲突 */
    public static final String EXTRA_IN_CHAIN = "in_chain";
    public static final int REQ_NODE = 21;
    public static final int REQ_LINK = 22;

    private static final String[] MODES = {"注入", "VLESS", "VMess", "Trojan", "Shadowsocks",
            "SOCKS5", "HTTP", "链路"};
    private static final String[] MODE_TYPE = {Node.INJECT, Node.VLESS, Node.VMESS, Node.TROJAN,
            Node.SS, Node.SOCKS, Node.HTTP, ""};
    private static final int MODE_CHAIN = MODES.length - 1;

    /* 三个样板都不含任何运营商/免流域名。192.0.2.1 是 TEST-NET-1 文档地址，
     * gateway.example.com 是占位域名，照着换成你自己的网关。 */

    /** ① 只换网关，不改请求：能跑通的最小配置。 */
    static final String SAMPLE_MIN = "listen_port=65080;\n"
            + "http_others=on;\n"
            + "http_direct=off;\n"
            + "http_ip=;\n"
            + "https_connect=on;\n"
            + "https_direct=off;\n"
            + "https_ip=192.0.2.1;\n"
            + "https_port=443;\n";

    /** ② 模板注入：把 CONNECT 首行改写成网关认的样子。 */
    static final String SAMPLE = "listen_port=65080;\n"
            + "http_others=on;\n"
            + "http_direct=off;\n"
            + "http_ip=;\n"
            + "http_port=;\n"
            + "http_del=\"\";\n"
            + "http_first=\"[M] [U] [V]\\r\\nHost: [H]\\r\\n\";\n"
            + "https_connect=on;\n"
            + "https_direct=off;\n"
            + "https_ip=192.0.2.1;\n"
            + "https_port=443;\n"
            + "https_del=\"\";\n"
            + "https_first=\"CONNECT [H] HTTP/1.1\\r\\nHost: [H]\\r\\n\";\n";

    /** ③ 网关写域名：交给「设置 → DNS → Bootstrap」解析，这里配一台明文 DNS 兜底。 */
    static final String SAMPLE_DOMAIN = "listen_port=65080;\n"
            + "http_others=on;\n"
            + "http_direct=off;\n"
            + "http_ip=;\n"
            + "https_connect=on;\n"
            + "https_direct=off;\n"
            + "https_ip=gateway.example.com;\n"
            + "https_port=443;\n"
            + "https_first=\"CONNECT [H] HTTP/1.1\\r\\nHost: [H]\\r\\n\";\n"
            + "dns_tcp=udp;\n"
            + "dns_ip=223.5.5.5;\n"
            + "dns_port=53;\n";

    private Profile profile;
    private Profile original;
    /** 进页面时的快照：判断「有没有改过」，决定返回要不要问一句 */
    private String born;
    private boolean newNode;
    private boolean isNew;
    private boolean inChain;
    private int modeIdx;
    private int chainIndex;

    private LinearLayout form;
    private final Map<String, EditText> fields = new LinkedHashMap<String, EditText>();
    /** 下拉框显示的是中文标签，写回模型的是另一套值；这里按 key 保存真实值。 */
    private final Map<String, String> picked = new LinkedHashMap<String, String>();
    private final Map<String, TextView> views = new LinkedHashMap<String, TextView>();

    public static void openNew(Context c) {
        c.startActivity(new Intent(c, EditActivity.class).putExtra(EXTRA_NEW, true));
    }

    public static void open(Context c, String profileId) {
        c.startActivity(new Intent(c, EditActivity.class).putExtra(EXTRA_PROFILE, profileId));
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Ui.lightStatus(this);
        Intent in = getIntent();
        String nodeJson = in.getStringExtra(EXTRA_NODE_JSON);
        inChain = in.getBooleanExtra(EXTRA_IN_CHAIN, false);
        if (in.hasExtra(EXTRA_NODE)) {
            newNode = true;
            profile = new Profile("节点");
            Node n = parseNode(nodeJson);
            if (n != null) profile.chain.add(n);
            modeIdx = indexOfType(profile.chain.get(0).type);
        } else if (in.getBooleanExtra(EXTRA_NEW, false)) {
            newNode = false;
            isNew = true;
            profile = new Profile("新配置");
            /* 需求：新建时默认协议是「注入」 */
            profile.chain.add(blank(Node.INJECT));
            modeIdx = 0;
        } else {
            Profile src = find(in.getStringExtra(EXTRA_PROFILE));
            profile = src == null ? new Profile("新配置") : src.draft();
            original = src;
            isNew = src == null;
            modeIdx = profile.chain.size() > 1 ? MODE_CHAIN
                    : indexOfType(profile.chain.isEmpty() ? Node.INJECT : profile.chain.get(0).type);
        }
        if (profile.chain.isEmpty()) profile.chain.add(blank(Node.INJECT));
        born = profile.toJson().toString();
        build();
    }

    private static Node parseNode(String json) {
        if (json == null) return null;
        try {
            return Node.fromJson(new JSONObject(json));
        } catch (Exception e) {
            return null;
        }
    }

    private static Profile find(String id) {
        if (id == null) return null;
        for (Profile p : Store.I.profiles) if (p.id.equals(id)) return p;
        return null;
    }

    private static int indexOfType(String type) {
        for (int i = 0; i < MODE_TYPE.length; i++) if (MODE_TYPE[i].equals(type)) return i;
        return 0;
    }

    /** 新建节点的初值：一律是空的。
     *  以前注入节点会自动塞一份模板进来，等于替用户预设了「配置就是这样」，
     *  还容易让人以为框里的东西已经生效。要模板点「填入示例」，不点就是一张白纸。 */
    private static Node blank(String type) {
        return new Node(type, "", 443);
    }

    /** 一个字都没填的节点：地址/名字/凭据/ini 全空。 */
    private static boolean blankHop(Node n) {
        return n.host.trim().length() == 0 && n.name.trim().length() == 0
                && n.uuid.trim().length() == 0 && n.password.trim().length() == 0
                && n.ini.trim().length() == 0;
    }

    /* --------------------------------------------------------------- 名字 */

    private static boolean defaultName(String s) {
        return s.length() == 0 || "新配置".equals(s) || "节点".equals(s) || "未命名".equals(s);
    }

    /** 手建的配置不再永远叫「新配置」：名字留空、或者还是默认值，就按内容猜一个。
     *  从链接/剪贴板导入的配置本来就带 remarks，不会走到这儿。 */
    private static String autoName(Profile p) {
        if (p.chain.isEmpty()) return "新配置";
        StringBuilder b = new StringBuilder(hopName(p.chain.get(0)));
        if (p.chain.size() > 1) b.append(" +").append(p.chain.size() - 1);
        return b.toString();
    }

    private static String hopName(Node n) {
        if (n.name.trim().length() > 0) return n.name.trim();
        if (Node.INJECT.equals(n.type)) {
            Ini c = Ini.parse(n.ini);
            String gw = c.httpsIp.length() > 0 ? c.httpsIp : c.httpIp;
            return gw.length() > 0 ? "注入 " + gw : "注入";
        }
        if (n.host.trim().length() > 0) return n.host.trim();
        return n.type.toUpperCase();
    }

    /* ------------------------------------------------------------------------- chrome */

    private void build() {
        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.BG);

        LinearLayout bar = Ui.row(this);
        bar.setPadding(Ui.dp(this, 14), Ui.dp(this, 10), Ui.dp(this, 14), Ui.dp(this, 6));
        TextView back = Ui.pill(this, "返回", 0xFFF1F3F6, Ui.INK);
        back.setOnClickListener(v -> leave());
        bar.addView(back);
        bar.addView(new View(this), Ui.lp(Ui.dp(this, 1), 1));
        TextView title = Ui.text(this,
                newNode ? "节点设置" : isNew ? "新建配置" : "配置设置", 17f, Ui.INK);
        title.setSingleLine(true);
        title.setEllipsize(android.text.TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams tp = Ui.wp(this, -2, 1, 10, 0, 8, 0);
        bar.addView(title, tp);
        TextView save = Ui.pill(this, newNode ? "确定" : "保存", Ui.ACCENT, Ui.WHITE);
        save.setOnClickListener(v -> saveAll());
        bar.addView(save);
        root.addView(bar, Ui.lp(-1, -2));

        form = Ui.column(this);
        ScrollView sc = Ui.page(this, form);
        LinearLayout.LayoutParams scLp = new LinearLayout.LayoutParams(-1, 0);
        scLp.weight = 1f;                 /* 高度 0 + weight=1 才是“剩下的都给列表” */
        root.addView(sc, scLp);
        setContentView(root);
        render();
    }

    private void render() {
        form.removeAllViews();
        fields.clear();
        picked.clear();
        views.clear();
        if (!newNode) {
            LinearLayout card = Ui.card(this);
            card.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 14));
            card.addView(Ui.label(this, "配置名称"));
            EditText name = Ui.field(this, "名称", profile.name);
            fields.put("__name", name);
            card.addView(name, Ui.lp(this, -1, -2, 0, 8, 0, 0));
            form.addView(card, Ui.block(this, 0, 10));
        }
        if (!newNode && profile.rawJson != null && profile.rawJson.length() > 0) {
            LinearLayout raw = Ui.card(this);
            raw.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 14));
            raw.addView(Ui.label(this, "完整配置（原样运行）"));
            raw.addView(Ui.text(this, "这份 JSON 会原样交给 xray，保留 outbounds/routing/dns；"
                    + "下面的字段只用于查看和单节点分享，修改字段不会改写原始 JSON。",
                    11.5f, Ui.MUTED));
            TextView editRaw = Ui.pill(this, "编辑原始 JSON", Ui.NEUTRAL, Ui.INK);
            editRaw.setOnClickListener(v -> Ui.promptDialog(this, "原始配置 JSON",
                    profile.rawJson, text -> {
                        java.util.List<Profile> ps = Links.parse(text);
                        if (ps.isEmpty()) {
                            Ui.toast(this, "没有识别到可用配置");
                            return;
                        }
                        Profile np = ps.get(0);
                        profile.rawJson = np.rawJson;
                        profile.chain = np.chain;
                        profile.rules = np.rules;
                        profile.name = np.name;
                        render();
                    }));
            raw.addView(editRaw);
            form.addView(raw, Ui.block(this, 0, 10));
        }
        if (newNode) {
            nodeCard();
        } else {
            typeCard();
            if (modeIdx == MODE_CHAIN) chainCard();
            else nodeCard();
        }
    }

    private void typeCard() {
        LinearLayout card = Ui.card(this);
        card.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 14));
        card.addView(Ui.label(this, "协议"));
        TextView val = Ui.text(this, MODES[modeIdx], 14.5f, Ui.INK);
        val.setSingleLine(true);
        val.setEllipsize(android.text.TextUtils.TruncateAt.END);
        views.put("mode", val);
        LinearLayout box = Ui.row(this);
        box.setBackground(Ui.roundStroke(0xFFFBFCFD, Ui.dp(this, 10), Ui.LINE, 1));
        box.setPadding(Ui.dp(this, 12), Ui.dp(this, 11), Ui.dp(this, 12), Ui.dp(this, 11));
        box.addView(val, Ui.wp(this, -2, 1, 0, 0, 8, 0));
        box.addView(Ui.text(this, "▾", 12f, Ui.MUTED));
        box.setOnClickListener(v -> pickMode());
        card.addView(box, Ui.lp(this, -1, -2, 0, 8, 0, 0));
        /* 链路的介绍只在真的选了「链路」时出现，平时别占地方 */
        if (modeIdx == MODE_CHAIN) {
            card.addView(Ui.text(this, "链路 = 多跳中转：先连第 1 跳，再由它把流量交给下一跳，"
                    + "最后一跳才出网。第一跳可以是注入节点。", 11.5f, Ui.MUTED),
                    Ui.lp(this, -1, -2, 0, 8, 0, 0));
        }
        form.addView(card, Ui.block(this, 0, 10));
    }

    private void pickMode() {
        Ui.choose(this, "协议", MODES, new Ui.Pick() {
            public void on(int i) {
                if (i == modeIdx) return;
                if (i == MODE_CHAIN) {
                    sync();
                    modeIdx = MODE_CHAIN;
                    /* 不要把那个还没填的空节点硬塞成「第一跳」：新配置一进来就是个空节点，
                     * 直接摆成第 1 跳只会让人以为链路天生自带一跳。没内容就清空，
                     * 让人自己点「＋ 添加新节点」。 */
                    if (profile.chain.size() == 1 && blankHop(profile.chain.get(0))) {
                        profile.chain.clear();
                    }
                    render();
                    return;
                }
                if (modeIdx == MODE_CHAIN && profile.chain.size() > 1) {
                    Ui.confirm(EditActivity.this, "切换成单节点",
                            "当前链路有 " + profile.chain.size() + " 跳，切换后只保留第 1 跳。",
                            new Runnable() {
                                public void run() {
                                    sync();
                                    collapse(i);
                                }
                            });
                    return;
                }
                sync();
                collapse(i);
            }
        });
    }

    private void collapse(int idx) {
        Node keep = profile.chain.isEmpty() ? blank(MODE_TYPE[idx]) : profile.chain.get(0);
        keep.type = MODE_TYPE[idx];
        List<Node> one = new ArrayList<Node>();
        one.add(keep);
        profile.chain = one;
        modeIdx = idx;
        render();
    }

    /* --------------------------------------------------------------------- node form */

    private Node node() {
        if (profile.chain.isEmpty()) return blank(MODE_TYPE[modeIdx]);
        chainIndex = Math.max(0, Math.min(chainIndex, profile.chain.size() - 1));
        return profile.chain.get(chainIndex);
    }

    private LinearLayout section(String label) {
        LinearLayout c = Ui.card(this);
        c.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 14));
        c.addView(Ui.label(this, label));
        return c;
    }

    /** 每种 xray 协议只摆自己的凭据字段，不再把所有字段混在一张「认证」卡里。 */
    private void nodeCard() {
        final Node n = node();
        if (Node.INJECT.equals(n.type)) {
            injectCard(n);
            return;
        }

        LinearLayout base = section("服务器");
        field(base, "节点名（可留空）", "name", n.name, false);
        LinearLayout hostRow = Ui.row(this);
        EditText host = Ui.field(this, "地址 / 域名", n.host);
        fields.put("host", host);
        hostRow.addView(host, Ui.wp(this, -2, 1, 0, 0, 8, 0));
        EditText port = Ui.field(this, "端口", String.valueOf(n.port));
        port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        fields.put("port", port);
        hostRow.addView(port, Ui.lp(this, Ui.dp(this, 92), -2, 0, 0, 0, 0));
        base.addView(hostRow, Ui.lp(-1, -2));
        form.addView(base, Ui.block(this, 0, 10));

        protocolCard(n);
        transportCard(n);
        securityCard(n);
    }

    private String protocolTitle(String type) {
        if (Node.VLESS.equals(type)) return "VLESS 参数";
        if (Node.VMESS.equals(type)) return "VMess 参数";
        if (Node.TROJAN.equals(type)) return "Trojan 参数";
        if (Node.SS.equals(type)) return "Shadowsocks 参数";
        if (Node.SOCKS.equals(type)) return "SOCKS5 参数";
        if (Node.HTTP.equals(type)) return "HTTP 代理参数";
        return "协议参数";
    }

    private void protocolCard(final Node n) {
        LinearLayout c = section(protocolTitle(n.type));
        String t = n.type;
        if (Node.VLESS.equals(t)) {
            field(c, "UUID", "uuid", n.uuid, false);
            field(c, "encryption（常规填 none）", "encryption", n.encryption, false);
            selectField(c, "flow", "flow", n.flow,
                    new String[]{"留空（不使用 flow）", "xtls-rprx-vision", "xtls-rprx-vision-udp443"},
                    new String[]{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}, null);
            c.addView(Ui.text(this, "encryption 常规填 none；VLESS Encryption 的那一长串"
                            + "（mlkem768x25519plus.…）原样贴进来即可。",
                    11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 0));
        } else if (Node.VMESS.equals(t)) {
            field(c, "UUID", "uuid", n.uuid, false);
            field(c, "alterId（0 = 关闭旧版 AEAD）", "alterId", String.valueOf(n.alterId), false);
            selectField(c, "加密方式（scy）", "vmessScy", n.vmessScy,
                    new String[]{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}, null);
            selectField(c, "packetEncoding（pcs，本机不参与运行，保留导入导出）", "vmessPcs", n.vmessPcs,
                    new String[]{"留空（默认）", "packetaddr", "xudp"},
                    new String[]{"", "packetaddr", "xudp"}, null);
        } else if (Node.TROJAN.equals(t)) {
            field(c, "密码", "password", n.password, true);
            uotRow(c, n);
        } else if (Node.SS.equals(t)) {
            selectField(c, "加密方式（method）", "method", n.method,
                    new String[]{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                            "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
                            "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
                            "none", "plain", "rc4-md5", "aes-128-cfb", "aes-256-cfb",
                            "chacha20-ietf"}, null);
            field(c, "密码", "password", n.password, true);
            uotRow(c, n);
        } else if (Node.SOCKS.equals(t) || Node.HTTP.equals(t)) {
            field(c, "用户名（可留空）", "user", n.user, false);
            field(c, "密码（可留空）", "password", n.password, true);
        }
        form.addView(c, Ui.block(this, 0, 10));
    }

    private static final String[] NETS = {"tcp", "ws", "grpc", "xhttp", "httpupgrade", "h2", "kcp", "quic"};
    /** h2 / QUIC 传输已被 Xray 26 移除，这里保留它们只为读老配置和导入链接 ——
     *  选择时会按官方迁移路径转成 XHTTP 发出，标签上直说，免得用户以为是新写法。 */
    private static final String[] NET_LABELS = {"tcp", "ws", "grpc", "xhttp", "httpupgrade",
            "h2（已并入 XHTTP）", "kcp", "quic（已并入 XHTTP/H3）"};

    /** 传输参数按 network 逐项展开：ws 才要 path/Host，grpc 才要 serviceName，
     *  KCP/QUIC 才要头伪装。这样卡片不会永远挂着一堆与当前传输无关的输入框。 */
    private void transportCard(final Node n) {
        LinearLayout c = section("传输方式");
        selectField(c, "network", "net", n.net, NET_LABELS, NETS, v -> {
            sync();
            n.net = v;
            render();
        });
        String net = n.net == null || n.net.length() == 0 ? "tcp" : n.net;
        if ("ws".equals(net)) {
            field(c, "path（WebSocket 路径）", "path", n.path, false);
            field(c, "Host（WebSocket 头）", "hostHdr", n.hostHdr, false);
        } else if ("grpc".equals(net)) {
            field(c, "serviceName", "serviceName", n.serviceName, false);
            field(c, "authority（可留空）", "hostHdr", n.hostHdr, false);
            selectField(c, "gRPC mode", "grpcMode", n.grpcMode,
                    new String[]{"gun（单流，默认）", "multi（多路复用，服务端要同开）"},
                    new String[]{"gun", "multi"}, null);
        } else if ("h2".equals(net) || "http".equals(net)) {
            field(c, "path（HTTP/2 路径）", "path", n.path, false);
            field(c, "Host（可留空）", "hostHdr", n.hostHdr, false);
            c.addView(Ui.text(this, "Xray 26 已移除 h2 传输，保存后会按官方迁移路径用 "
                            + "XHTTP stream-one（H2）发出；服务端也要是支持 XHTTP 的版本。",
                    11.5f, Ui.WARN), Ui.lp(this, -1, -2, 0, 8, 0, 0));
        } else if ("httpupgrade".equals(net)) {
            field(c, "path", "path", n.path, false);
            field(c, "Host（可留空）", "hostHdr", n.hostHdr, false);
        } else if ("xhttp".equals(net)) {
            field(c, "path", "path", n.path, false);
            field(c, "Host（可留空）", "hostHdr", n.hostHdr, false);
            selectField(c, "mode", "xhttpMode", n.xhttpMode,
                    new String[]{"auto（跟随服务端）", "packet-up", "stream-up", "stream-one"},
                    new String[]{"auto", "packet-up", "stream-up", "stream-one"}, null);
            areaField(c, "extra（JSON，可留空）", "xhttpExtra", n.xhttpExtra, 3);
            c.addView(Ui.text(this, "extra 用于 xmux、downloadSettings 这类高级参数，"
                            + "填一段 JSON 对象即可；格式错误会被忽略，不会导致启动失败。",
                    11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 0));
        } else if ("kcp".equals(net)) {
            field(c, "seed（可留空）", "kcpSeed", n.kcpSeed, false);
            field(c, "mtu（默认 1350）", "kcpMtu", String.valueOf(n.kcpMtu), false);
            field(c, "tti（默认 50）", "kcpTti", String.valueOf(n.kcpTti), false);
            selectField(c, "KCP 头伪装", "headerType", n.headerType,
                    new String[]{"none", "srtp", "wechat-video", "dtls", "utp", "wireguard"}, null);
            c.addView(Ui.text(this, "Xray 26 把 KCP 的头伪装和 seed 迁进了 finalmask"
                            + "（mkcp-legacy），这里填的值会自动转过去，不用手写 JSON。",
                    11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 0));
        } else if ("quic".equals(net)) {
            field(c, "key（可留空）", "quicKey", n.quicKey, false);
            selectField(c, "QUIC 加密（security，已不生效）", "quicSecurity", n.quicSecurity,
                    new String[]{"none", "aes-128-gcm", "chacha20-poly1305"}, null);
            selectField(c, "QUIC 头伪装（已不生效）", "headerType", n.headerType,
                    new String[]{"none", "srtp", "wechat-video", "dtls", "utp", "wireguard"}, null);
            c.addView(Ui.text(this, "Xray 26 已移除 QUIC 传输，保存后会按官方迁移路径用 "
                            + "XHTTP stream-one（H3，ALPN 补 h3）发出。",
                    11.5f, Ui.WARN), Ui.lp(this, -1, -2, 0, 8, 0, 0));
        } else {
            selectField(c, "TCP 头伪装（headerType）", "headerType", n.headerType,
                    new String[]{"none（裸 TCP）", "http（伪装成 HTTP 请求）"},
                    new String[]{"none", "http"}, v -> {
                        sync();
                        n.headerType = v;
                        render();
                    });
            if ("http".equals(n.headerType)) {
                field(c, "path（伪装路径，逗号分隔可多个）", "path", n.path, false);
                field(c, "Host（伪装 Host，逗号分隔可多个）", "hostHdr", n.hostHdr, false);
            } else {
                c.addView(Ui.text(this, "纯 TCP，没有额外传输参数。", 11.5f, Ui.MUTED),
                        Ui.lp(this, -1, -2, 0, 8, 0, 0));
            }
        }
        areaField(c, "finalmask（高级 JSON，可留空）", "finalMask", n.finalMask, 3);
        c.addView(Ui.text(this, "finalmask 写了就按原样交给 xray，覆盖上面生成的 KCP 伪装；"
                        + "形如 {\"tcp\":[…],\"udp\":[…]}，不熟就留空。",
                11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 0));
        form.addView(c, Ui.block(this, 0, 10));
    }

    private void securityCard(final Node n) {
        LinearLayout c = section("传输层安全");
        selectField(c, "security", "security", n.security,
                new String[]{"none", "tls", "reality"}, v -> {
                    sync();
                    n.security = v;
                    render();
                });
        String sec = n.security == null ? "none" : n.security;
        if ("tls".equals(sec)) {
            field(c, "SNI（证书域名）", "sni", n.sni, false);
            field(c, "ALPN（h2,http/1.1）", "alpn", n.alpn, false);
            selectField(c, "fingerprint（uTLS）", "fp", n.fp,
                    new String[]{"留空（不伪装）", "chrome", "firefox", "safari", "ios", "android",
                            "edge", "360", "qq", "random", "randomized"},
                    new String[]{"", "chrome", "firefox", "safari", "ios", "android",
                            "edge", "360", "qq", "random", "randomized"}, null);
            switchRow(c, "跳过证书校验（allowInsecure）", n.allowInsecure, on -> {
                n.allowInsecure = on;
            });
            field(c, "ECH 配置（echConfigList，可留空）", "ech", n.ech, false);
            field(c, "按名字校验证书（verifyPeerCertByName，可留空）", "verifyPeer", n.verifyPeer, false);
            field(c, "证书 pin（pinnedPeerCertSha256，64 位十六进制，可留空）", "pinnedCA", n.pinnedCA, false);
            if (n.pinnedCA != null && n.pinnedCA.length() > 0 && n.allowInsecure) {
                c.addView(Ui.text(this, "钉了证书就不再跳过校验：pin 与 allowInsecure 同时开时，"
                                + "allowInsecure 不生效（与 v2rayNG 一致）。",
                        11.5f, Ui.WARN), Ui.lp(this, -1, -2, 0, 8, 0, 0));
            }
        } else if ("reality".equals(sec)) {
            field(c, "SNI（对端伪装域名）", "sni", n.sni, false);
            field(c, "fingerprint（默认 chrome）", "fp", n.fp, false);
            field(c, "reality publicKey（pbk）", "pbk", n.pbk, false);
            field(c, "reality shortId（sid）", "sid", n.sid, false);
            field(c, "reality spiderX（默认 /）", "spx", n.spx, false);
            field(c, "mldsa65Verify（可留空）", "mldsa", n.mldsa, false);
            c.addView(Ui.text(this, "REALITY 不做 CA 校验，allowInsecure 不参与。"
                            + "mldsa65Verify 是 Xray 25.9+ 的后量子验签串，服务端没开就留空。",
                    11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 0));
        } else {
            c.addView(Ui.text(this, "不加密。只有 tcp 才适合裸连，公共网络建议开 TLS 或 REALITY。",
                    11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 0));
            /* Xray 26 起，VLESS/Trojan 裸连只允许内网地址：公网地址会在配置校验阶段
             * 直接被拒（"without TLS or other encryption is prohibited"），进程起不来。
             * 这类配置存得下但一定跑不通，所以在编辑页先说清楚。 */
            if ((Node.VLESS.equals(n.type) || Node.TROJAN.equals(n.type)) && !privateHost(n.host)) {
                c.addView(Ui.text(this, n.type.toUpperCase()
                                + " 明文只允许连内网地址：Xray 26 会拒绝启动公网明文 "
                                + n.type.toUpperCase() + "。请把 security 改成 tls / reality，"
                                + "或改用 VMess / SS。",
                        11.5f, Ui.WARN), Ui.lp(this, -1, -2, 0, 8, 0, 0));
            }
        }
        form.addView(c, Ui.block(this, 0, 10));
    }

    /** 可选值输入框：点一下弹选择，最后一项允许手填，导入进来的非常规值不会丢。 */
    private void selectField(LinearLayout parent, String label, String key, String value,
                             String[] options, java.util.function.Consumer<String> onChange) {
        selectField(parent, label, key, value, options, options, onChange);
    }

    /** labels 给用户看，values 写回模型；两者等长，最后自动追加「自定义…」。 */
    private void selectField(LinearLayout parent, String label, String key, String value,
                             final String[] labels, final String[] values,
                             final java.util.function.Consumer<String> onChange) {
        parent.addView(Ui.text(this, label, 11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 4));
        final EditText e = Ui.field(this, "", displayValue(value, labels, values));
        picked.put(key, value == null ? "" : value);
        e.setFocusable(false);
        e.setCursorVisible(false);
        e.setClickable(true);
        e.setOnClickListener(v -> {
            final String[] items = new String[labels.length + 1];
            System.arraycopy(labels, 0, items, 0, labels.length);
            items[labels.length] = "自定义…";
            Ui.choose(this, label, items, idx -> {
                if (idx == labels.length) {
                    Ui.inputDialog(this, label, picked.get(key), s -> {
                        String nv = s == null ? "" : s.trim();
                        e.setText(nv);
                        picked.put(key, nv);
                        if (onChange != null) onChange.accept(nv);
                    });
                } else {
                    e.setText(items[idx]);
                    picked.put(key, values[idx]);
                    if (onChange != null) onChange.accept(values[idx]);
                }
            });
        });
        fields.put(key, e);
        parent.addView(e, Ui.lp(-1, -2));
    }

    private static String displayValue(String value, String[] labels, String[] values) {
        if (value == null) return "";
        for (int i = 0; i < values.length && i < labels.length; i++) {
            if (values[i].equals(value)) return labels[i];
        }
        return value;
    }

    /** 注入节点的 UDP 转换：选一个现有 UDP 节点承接 UDP，并决定它的服务器连接
     *  是经注入网关（保免流）还是直连（低延迟）。 */
    private void udpCard(final Node n) {
        LinearLayout card = section("UDP 转换");
        card.addView(Ui.text(this,
                "HTTP 注入只能承载 TCP。UDP（游戏、语音、QUIC）默认会被丢弃；"
                        + "在这里选一个支持 UDP 的节点来承接，就不用为了 UDP 把整条链路改成直连。",
                11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 6, 0, 0));

        final Node u = n.udpNode;
        LinearLayout status = Ui.row(this);
        status.setPadding(0, Ui.dp(this, 8), 0, 0);
        status.addView(Ui.text(this, "当前", 12f, Ui.MUTED), Ui.lp(Ui.dp(this, 34), -2));
        TextView cur = Ui.text(this, u == null ? "未启用（UDP 按路由策略丢弃）"
                        : u.type.toUpperCase() + " · " + u.addr() + (u.name.length() > 0 ? " · " + u.name : ""),
                12.5f, u == null ? Ui.MUTED : Ui.INK);
        cur.setSingleLine(true);
        cur.setEllipsize(android.text.TextUtils.TruncateAt.END);
        status.addView(cur, Ui.wp(this, -2, 1, 0, 0, 0, 0));
        card.addView(status, Ui.lp(-1, -2));

        LinearLayout ops = Ui.row(this);
        ops.setPadding(0, Ui.dp(this, 8), 0, 0);
        TextView pick = Ui.pill(this, u == null ? "选择 UDP 节点" : "更换节点", Ui.ACCENT, Ui.WHITE);
        pick.setOnClickListener(v -> pickUdpNode(n));
        ops.addView(pick, Ui.share(this, 0, 5));
        TextView off = Ui.pill(this, "关闭 UDP 转换", Ui.NEUTRAL, Ui.INK);
        off.setEnabled(u != null);
        off.setAlpha(u == null ? 0.45f : 1f);
        off.setOnClickListener(v -> {
            if (n.udpNode == null) return;
            sync();
            n.udpNode = null;
            render();
        });
        ops.addView(off, Ui.share(this, 5, 0));
        card.addView(ops, Ui.lp(-1, -2));

        if (u != null) {
            final boolean via = n.udpViaInject;
            LinearLayout modes = Ui.row(this);
            modes.setPadding(0, Ui.dp(this, 10), 0, 0);
            TextView viaPill = Ui.pill(this, "经注入节点", via ? Ui.ACCENT : Ui.NEUTRAL,
                    via ? Ui.WHITE : Ui.INK);
            viaPill.setOnClickListener(v -> {
                if (n.udpViaInject) return;
                if (!Node.udpOverTcp(u)) {
                    Ui.info(this, "这个节点不能经注入网关",
                            "它的 UDP 是独立发往服务器的，注入网关（HTTP CONNECT）带不了。\n"
                                    + "换成 VLESS / VMess，或给 Trojan / SS 打开 uot；"
                                    + "也可以直接用「直连该节点」。");
                    return;
                }
                sync();
                n.udpViaInject = true;
                render();
            });
            modes.addView(viaPill, Ui.share(this, 0, 5));
            TextView directPill = Ui.pill(this, "直连该节点", !via ? Ui.ACCENT : Ui.NEUTRAL,
                    !via ? Ui.WHITE : Ui.INK);
            directPill.setOnClickListener(v -> {
                if (!n.udpViaInject) return;
                sync();
                n.udpViaInject = false;
                render();
            });
            modes.addView(directPill, Ui.share(this, 5, 0));
            card.addView(modes, Ui.lp(-1, -2));

            card.addView(Ui.text(this, via
                            ? "UDP 承载节点的服务器连接先经注入网关：免流仍然生效，"
                            + "代价是多一跳、延迟略高。只适用于 UDP 走 TCP 隧道的节点。"
                            : "UDP 直接发往这个节点：延迟最低，不经过注入网关。"
                            + "如果这个节点本身也支持免流（本来就在免流范围内，或由免流通道落地），"
                            + "这部分流量同样不走通用流量；节点不带免流时才按普通流量计费。",
                    11.5f, via ? Ui.ACCENT : Ui.MUTED), Ui.lp(this, -1, -2, 0, 7, 0, 0));

            if (via && !Node.udpOverTcp(u)) {
                card.addView(Ui.text(this,
                                "该节点（" + u.type.toUpperCase() + "）的 UDP 不走 TCP 隧道，"
                                        + "「经注入节点」不会生效；启动时会自动按直连处理。",
                        11.5f, Ui.WARN), Ui.lp(this, -1, -2, 0, 6, 0, 0));
            } else if (via && ("kcp".equals(u.net) || "quic".equals(u.net))) {
                card.addView(Ui.text(this,
                                "该节点用 " + u.net + " 传输，服务器连接本身就是 UDP，"
                                        + "无法经注入网关拨号；请改「直连该节点」。",
                        11.5f, Ui.WARN), Ui.lp(this, -1, -2, 0, 6, 0, 0));
            }

            boolean udpOk = Profile.UDP_PROXY.equals(profile.effectiveUdpPolicy());
            boolean quicOk = Profile.UDP_PROXY.equals(profile.effectiveQuicPolicy());
            if (!udpOk || !quicOk) {
                String what = !udpOk && !quicOk ? "UDP 和 QUIC"
                        : (!udpOk ? "UDP" : "QUIC（443）");
                String now = !udpOk ? policyName(profile.effectiveUdpPolicy())
                        : policyName(profile.effectiveQuicPolicy());
                card.addView(Ui.text(this,
                                "路由里的 " + what + " 策略是「" + now + "」，这部分流量不会走 UDP 转换。",
                        11.5f, Ui.WARN), Ui.lp(this, -1, -2, 0, 8, 0, 0));
                TextView fix = Ui.pill(this, "把 UDP / QUIC 设为代理", Ui.ACCENT_SOFT, Ui.ACCENT);
                fix.setOnClickListener(v -> {
                    sync();
                    profile.udpPolicy = Profile.UDP_PROXY;
                    profile.quicPolicy = Profile.UDP_PROXY;
                    render();
                });
                card.addView(fix, Ui.lp(this, -2, -2, 0, 8, 0, 0));
            } else {
                card.addView(Ui.text(this, "路由里的 UDP / QUIC 已经是「代理」，保存后生效。",
                        11f, Ui.OK), Ui.lp(this, -1, -2, 0, 7, 0, 0));
            }
        }
        form.addView(card, Ui.block(this, 0, 10));
    }

    private static String policyName(String p) {
        if (Profile.UDP_BLOCK.equals(p)) return "丢弃";
        if (Profile.UDP_DIRECT.equals(p)) return "直连";
        return "代理";
    }

    private void pickUdpNode(final Node n) {
        final List<Node> pool = new ArrayList<Node>();
        final List<String> labels = new ArrayList<String>();
        /* 和节点一起记下来源（配置 id + 链内下标）：副本保存后如果列表里的原节点被
         * 订阅更新或手改，启动时才能按这三条线索同步，而不是继续连旧地址。 */
        final List<String> poolPid = new ArrayList<String>();
        final List<Integer> poolIdx = new ArrayList<Integer>();
        labels.add("不使用（关闭 UDP 转换）");
        for (Profile p : Store.I.profiles) {
            for (int i = 0; i < p.chain.size(); i++) {
                Node hop = p.chain.get(i);
                if (!Node.udpCapable(hop.type)) continue;  // 注入/HTTP 承载不了 UDP
                if (hop.host == null || hop.host.trim().length() == 0 || hop.port <= 0) continue;
                pool.add(hop);
                poolPid.add(p.id);
                poolIdx.add(i);
                labels.add(p.name + " · " + hop.title() + " · " + hop.type.toUpperCase()
                        + (hop.netId() == com.lcs.tproxy.model.Kinds.NET_TCP ? "" : " / " + hop.net));
            }
        }
        if (pool.isEmpty()) {
            Ui.info(this, "没有可用的 UDP 节点",
                    "先添加一个 VLESS / VMess / Trojan / ShadowSocks / SOCKS5 节点，再回来选。");
            return;
        }
        Ui.choose(this, "用哪个节点承载 UDP", labels.toArray(new String[0]), idx -> {
            sync();
            if (idx == 0) {
                n.udpNode = null;
                n.udpSrcProfile = "";
                n.udpSrcIndex = -1;
                n.udpSrcFp = "";
            } else {
                Node src = pool.get(idx - 1);
                Node pick = src.copy();
                n.udpNode = pick;
                /* 默认选能保免流的模式；节点带不动 UDP-over-TCP 时退回直连，并让上面的
                 * 黄色提示解释原因，别让用户以为免流还在。 */
                n.udpViaInject = Node.udpOverTcp(pick)
                        && pick.netId() != com.lcs.tproxy.model.Kinds.NET_KCP
                        && pick.netId() != com.lcs.tproxy.model.Kinds.NET_QUIC;
                com.lcs.tproxy.model.NodeSync.bindSource(n, poolPid.get(idx - 1), poolIdx.get(idx - 1), src);
            }
            render();
        });
    }

    private void injectCard(final Node n) {
        /* UDP 转换只对「单节点的注入配置」有意义。链式配置每一跳连到下一跳，
         * 再插一个 UDP 分流会和链路语义打架，所以链路/链路中的一跳都不显示。 */
        boolean showUdp = !newNode && !inChain && modeIdx != MODE_CHAIN && profile.chain.size() == 1;
        if (showUdp) udpCard(n);

        LinearLayout card = Ui.card(this);
        card.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 14));
        card.addView(Ui.label(this, "注入配置（key=value; 原文）"));

        /* 框里就是 ini 本身，不再预填一份模板。新建的注入节点是空的 ——
         * 空 ini 的含义很明确：这一跳只是把连接原样转发。
         * 想要一个能跑的样板，点上面「填入示例」。 */
        final String seed = n.ini;
        final EditText area = Ui.area(this, "留空 = 原样转发。点上面的「填入示例」看一个能跑的样子", seed, 12);
        fields.put("ini", area);

        /* 按钮放在输入框上面：编辑长文本时不用来回翻页找按钮 */
        FlowLayout ops = new FlowLayout(this);
        TextView sample = Ui.pill(this, "填入示例", 0xFFF1F3F6, Ui.INK);
        sample.setOnClickListener(v -> {
            final String[] names = {"① 只换网关（最小可用）", "② 模板注入", "③ 网关是域名 + DNS"};
            final String[] texts = {SAMPLE_MIN, SAMPLE, SAMPLE_DOMAIN};
            Ui.choose(this, "选一个示例", names, idx -> {
                if (area.getText().toString().trim().length() == 0) {
                    area.setText(texts[idx]);
                } else {
                    Ui.confirm(this, "覆盖当前配置", "示例会替换掉现在输入的内容。",
                            () -> area.setText(texts[idx]));
                }
            });
        });
        ops.addView(sample);
        TextView norm = Ui.pill(this, "解析并规范化", 0xFFF1F3F6, Ui.INK);
        norm.setOnClickListener(v -> area.setText(Ini.parse(area.getText().toString()).dump()));
        ops.addView(norm);
        TextView help = Ui.pill(this, "占位符怎么写", Ui.ACCENT_SOFT, Ui.ACCENT);
        help.setOnClickListener(v -> Ui.info(this, "注入模板占位符", HELP));
        ops.addView(help);
        TextView ref = Ui.pill(this, "字段速查", Ui.ACCENT_SOFT, Ui.ACCENT);
        ref.setOnClickListener(v -> Ui.info(this, "配置字段速查", REFERENCE));
        ops.addView(ref);
        TextView dnsHelp = Ui.pill(this, "DNS 怎么填", Ui.ACCENT_SOFT, Ui.ACCENT);
        dnsHelp.setOnClickListener(v -> Ui.info(this, "这一跳的 DNS", DNS_HELP));
        ops.addView(dnsHelp);
        card.addView(ops, Ui.lp(this, -1, -2, 0, 8, 0, 0));

        card.addView(area, Ui.lp(this, -1, Ui.dp(this, 280), 0, 8, 0, 0));

        final TextView sum = Ui.text(this, summ(seed), 11.5f, Ui.MUTED);
        card.addView(sum, Ui.lp(this, -1, -2, 0, 8, 0, 0));
        area.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            public void onTextChanged(CharSequence s, int a, int b, int c) {
            }

            public void afterTextChanged(Editable e) {
                sum.setText(summ(e.toString()));
            }
        });

        /* 占位符说明直接摆在页面上：不能只藏在按钮后面，不然第一眼根本不知道 [H]/[M]/[U]/[V] 是什么 */
        LinearLayout legend = Ui.column(this);
        legend.setBackground(Ui.roundStroke(0xFFFBFCFD, Ui.dp(this, 10), Ui.LINE, 1));
        legend.setPadding(Ui.dp(this, 12), Ui.dp(this, 10), Ui.dp(this, 12), Ui.dp(this, 10));
        legend.addView(Ui.text(this, "怎么用", 12f, Ui.INK));
        legend.addView(Ui.text(this,
                "1) 先定这一跳要干什么：只换网关（示例①）/ 改请求首行（示例②）/ 网关是域名（示例③）。\n"
                        + "2) 填 https_ip + https_port —— 这是流量真正去的地方；http_ip 留空表示 80 端口也交给 https 槽。\n"
                        + "3) 要改首行就写 https_first / http_first，不改就留空，原样转发。\n"
                        + "4) 保存前看上面那行灰字摘要：两个槽各是「注入 / 直连 / 原样转发」，一眼能对。\n"
                        + "5) 拿不准就点「填入示例」，再把 IP 和域名换成你自己的。",
                11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 6, 0, 0));
        legend.addView(Ui.text(this, "模板占位符", 12f, Ui.INK),
                Ui.lp(this, -1, -2, 0, 8, 0, 0));
        legend.addView(Ui.text(this,
                "[M] 方法　https_first 恒为 CONNECT；http_first 是 GET / POST / …\n"
                        + "[H] 主机　https_first 里是「host:端口」（example.com:443）；"
                        + "http_first 里是客户端请求的 Host 头（example.com）\n"
                        + "[U] 路径　原始请求行里的目标，含 ?a=1（只有 http_first 有意义）\n"
                        + "[V] 版本　HTTP/1.1", 11.5f, Ui.MUTED),
                Ui.lp(this, -1, -2, 0, 6, 0, 0));
        legend.addView(Ui.text(this,
                "[H]=[host]、[M]=[method]、[U]=[uri]、[V]=[version]，两种写法等价。\n"
                        + "模板只替换请求行，客户端其余请求头原样保留；"
                        + "http_del / https_del 里列出的头会被删掉（逗号分隔，按名字前缀匹配）。\n"
                        + "换行写 \\r\\n，结尾那个空行程序自己补，不要多写。",
                11f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 6, 0, 0));
        legend.addView(Ui.text(this,
                "开关\n"
                        + "http_others=on/off　　80 端口用不用 http 槽\n"
                        + "https_connect=on/off　其它端口用不用 https 槽\n"
                        + "http_direct / https_direct=on　　该槽直连目标、不注入模板（会走真实网络）\n"
                        + "http_del / https_del　要删掉的请求头名字，逗号分隔\n"
                        + "http_ip / https_ip 没填 → 不直连，交给另一侧槽（http 没填就由 https 接管）",
                11f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 6, 0, 0));
        card.addView(legend, Ui.lp(this, -1, -2, 0, 10, 0, 0));
        form.addView(card, Ui.block(this, 0, 10));

        LinearLayout tips = Ui.card(this);
        tips.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 14));
        tips.addView(Ui.text(this, "端口 80 的请求走 http 槽（http_ip/http_port + http_first）；"
                + "其它端口（443/8443/…）走 https 槽（https_ip/https_port + https_first）。\n"
                + "http_ip 没填时，80 端口交给 https 槽接管：走 CONNECT 隧道，不注入 http_first"
                + "—— 原版就是这样（空的 HttpIp 会填哨兵值，走 https 槽）。\n"
                + "http_others=off 是另一回事：整个 http 槽关掉，80 端口直接连目标，会走真实网络。\n"
                + "注意：_ip 没填不等于直连。只有 _direct=on 才直连；"
                + "_ip 空着又没开 _direct 时直连会把流量放回真实网络，"
                + "免流卡上就是白白跑流量。\n"
                + "网关写域名时，「设置 → DNS → Bootstrap」开着就先过它解析一次，"
                + "结果缓存到断开；没开才用下面的 dns_* 或系统解析。", 11.5f, Ui.MUTED));
        form.addView(tips, Ui.block(this, 0, 10));
    }

    private static final String HELP =
            "http_first / https_first 里能用的占位符（区分大小写，两种写法等价）：\n\n"
                    + "［M］[method]  →  方法。https_first 恒为 CONNECT；http_first 里是 GET / POST。\n"
                    + "［H］[host]    →  https_first：目标 host:端口（example.com:443）；"
                    + "http_first：客户端请求的 Host 头（example.com）。\n"
                    + "［U］[uri]     →  http_first：原始请求目标，含查询串（/a?b=1）。"
                    + "https_first 用不到。\n"
                    + "［V］[version] →  HTTP/1.1。\n\n"
                    + "模板只替换请求行，客户端其余请求头原样保留；"
                    + "http_del / https_del 列出的头会被删掉。\n"
                    + "写 \\r\\n 表示换行，结尾空行程序会补，不要自己多写一个。\n\n"
                    + "通用形态（换成你自己的网关和域名）：\n"
                    + "https_first=\"CONNECT [H] HTTP/1.1\\r\\nHost: [H]\\r\\n\"\n"
                    + "http_first=\"[M] [U] [V]\\r\\nHost: [H]\\r\\n\"\n"
                    + "http_del=\"Host,X-Online-Host\"　← 模板里已经写了 Host 时，把客户端的 Host 删掉\n\n"
                    + "免流网关常见的伪装写法是往首行塞一个它认的域名，例如\n"
                    + "https_first=\"CONNECT [H]@你的域名 HTTP/1.1\\r\\nHost: 你的域名\\r\\n\"\n"
                    + "这类域名每个运营商都不一样，示例里不预置，自己填。";

    private static final String REFERENCE =
            "监听\n"
                    + "listen_port=65080　　本地 HTTP 代理端口；0 或空 = 随机\n"
                    + "local_ip=127.0.0.1　　只监听本机\n\n"
                    + "HTTP 槽（80 端口）\n"
                    + "http_others=on/off　　off = 关掉 http 槽，80 端口直连目标\n"
                    + "http_direct=on/off　　on = 直连目标，不注入（会走真实网络）\n"
                    + "http_ip=网关地址　　　可写域名，由 Bootstrap / dns_* 解析\n"
                    + "http_port=80　　　　　网关端口\n"
                    + "http_first=模板　　　 留空 = 原样转发\n"
                    + "http_del=Host,X-...　 要删的请求头，逗号分隔\n\n"
                    + "HTTPS 槽（其它端口）\n"
                    + "https_connect=on/off\n"
                    + "https_direct=on/off\n"
                    + "https_ip / https_port\n"
                    + "https_first / https_del\n\n"
                    + "注入行为\n"
                    + "inject_fallback=on/off　模板被网关拒绝后，是否退回普通 CONNECT 再试（默认 off）\n"
                    + "UDP 不走 ini：在页面顶部「UDP 转换」里选一个支持 UDP 的节点承接\n\n"
                    + "DNS（只影响这一跳自己的解析）\n"
                    + "dns_tcp=http|udp|tcp|tls　用哪种查询，默认 http\n"
                    + "dns_url=https://...　　　　DoH / HTTPDNS 地址，dns_tcp=http 时生效\n"
                    + "dns_ip=223.5.5.5　　　　　明文 DNS 地址，udp/tcp/tls 时生效，可写域名\n"
                    + "dns_port=53　　　　　　　　明文端口；DoT 写 853 或留空\n"
                    + "dns_listen_port=5353　　　本机 UDP DNS 前端，0 = 关\n\n"
                    + "旧字段（只为读老配置，不用手写）：\n"
                    + "remarks / apn / v2ray_domain / conf_model / http_fallback /\n"
                    + "bypass_flow / worker_proc / daemon / uid\n\n"
                    + "优先级：节点里写了 dns_url / dns_ip 就用节点的；没写才继承「设置 → DNS」。\n"
                    + "「设置 → DNS → Bootstrap」开着时，所有域名先过它，再轮到 dns_*。";

    /** 注入节点自己的解析器。只影响本跳配置里的主机名，和「设置 → DNS」不是一回事。 */
    private static final String DNS_HELP =
            "这一跳自己的解析器，只影响本跳配置里的域名\n"
                    + "（http_ip / https_ip / dns_url 里的主机名）。\n\n"
                    + "dns_tcp 决定用哪种查询\n"
                    + "  http（默认）  看 dns_url：有就 DoH / HTTPDNS；没有就用 dns_ip 走 UDP；\n"
                    + "                两个都没填时：代理策略下拒绝解析，直连策略下才走系统\n"
                    + "  udp           明文 UDP，问 dns_ip:dns_port\n"
                    + "  tcp           明文 TCP，问 dns_ip:dns_port\n"
                    + "  tls           DoT，问 dns_ip:853（dns_port 写 53 也按 853 走）\n\n"
                    + "dns_url 三种写法（dns_tcp=http 时生效）\n"
                    + "  https://223.5.5.5/dns-query       DoH，POST application/dns-message\n"
                    + "  http://119.29.29.29/d?dn={domain}  HTTPDNS，{domain} 替换成域名\n"
                    + "  http://119.29.29.29/d              没有 {domain} 就自动追加 ?dn=域名\n\n"
                    + "dns_ip / dns_port\n"
                    + "  明文 DNS 的地址和端口。默认 53；DoT 用 853。dns_ip 也能写域名。\n\n"
                    + "dns_listen_port\n"
                    + "  在本机 127.0.0.1 开一个 UDP DNS 前端：只答 A 记录，解析失败返回空答案\n"
                    + "  （不是 NXDOMAIN）。0 = 不开。它不会自动接管应用的 DNS，\n"
                    + "  要手动把应用的 DNS 指到 127.0.0.1:这个端口。\n\n"
                    + "主机名谁来解析\n"
                    + "  dns_url / dns_ip 里写域名时，先过「设置 → DNS → Bootstrap」；\n"
                    + "  Bootstrap 没开就交给系统解析。\n\n"
                    + "优先级\n"
                    + "  Bootstrap（全局开关）→ 节点 dns_url / dns_ip → 全局 DNS（节点两个都空才继承）\n"
                    + "  → 系统解析（只有 DNS 策略=直连时才会走到）";

    private static String summ(String ini) {
        Ini c = Ini.parse(ini);
        StringBuilder sb = new StringBuilder();
        sb.append("http ").append(c.httpIp.length() > 0 ? c.httpIp : "-").append(':').append(c.httpPort)
                .append(tag(c.httpOn, c.httpDirect, c.httpIp, c.httpFirst));
        sb.append("   https ").append(c.httpsIp.length() > 0 ? c.httpsIp : "-").append(':').append(c.httpsPort)
                .append(tag(c.httpsOn, c.httpsDirect, c.httpsIp, c.httpsFirst));
        if (c.dnsUrl.length() > 0) sb.append("\nDNS ").append(c.dnsUrl);
        return sb.toString();
    }

    /** 一侧槽的实际状态：关闭 / 直连（不注入）/ 没填 ip 交给另一侧 / 注入模板 / 原样转发 */
    private static String tag(boolean on, boolean direct, String ip, String first) {
        if (!on) return "（关闭 → 直连）";
        if (direct) return "（直连·不注入）";
        if (ip.length() == 0) return "（没填 ip → 交给另一侧）";
        return first.length() > 0 ? "（注入模板）" : "（原样转发）";
    }

    /* -------------------------------------------------------------------- chain card */

    private void chainCard() {
        LinearLayout head = Ui.card(this);
        head.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 14));
        head.addView(Ui.label(this, "链路（从本机到出口）"));
        head.addView(Ui.text(this, path(), 11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 6, 0, 0));
        String err = Conf.chainError(profile);
        if (err != null) head.addView(Ui.text(this, err, 11.5f, Ui.WARN),
                Ui.lp(this, -1, -2, 0, 6, 0, 0));
        String warn = err == null ? Conf.chainWarning(profile) : null;
        if (warn != null) head.addView(Ui.text(this, warn, 11.5f, Ui.WARN),
                Ui.lp(this, -1, -2, 0, 6, 0, 0));
        form.addView(head, Ui.block(this, 0, 10));

        for (int i = 0; i < profile.chain.size(); i++) hopCard(i);
        addButtons();
    }

    private String path() {
        StringBuilder sb = new StringBuilder("本机");
        for (Node n : profile.chain) sb.append(" → ").append(n.host.length() > 0 ? n.host : n.type.toUpperCase());
        sb.append(" → 目标");
        return sb.toString();
    }

    private void hopCard(final int idx) {
        final Node n = profile.chain.get(idx);
        LinearLayout card = Ui.card(this);
        card.setPadding(Ui.dp(this, 14), Ui.dp(this, 10), Ui.dp(this, 14), Ui.dp(this, 12));
        LinearLayout top = Ui.row(this);
        TextView num = Ui.text(this, String.valueOf(idx + 1), 13f, Ui.ACCENT);
        num.setBackground(Ui.round(Ui.ACCENT_SOFT, Ui.dp(this, 8)));
        num.setPadding(Ui.dp(this, 8), Ui.dp(this, 2), Ui.dp(this, 8), Ui.dp(this, 3));
        top.addView(num);
        LinearLayout col = Ui.column(this);
        col.addView(Ui.text(this, idx == 0 ? "第一跳（本机直连）" : "第 " + (idx + 1) + " 跳",
                13.5f, Ui.INK));
        col.addView(Ui.text(this, n.summary() + (n.localHop() ? " · 本地引擎" : ""), 11.5f, Ui.MUTED),
                Ui.lp(this, -1, -2, 0, 3, 0, 0));
        top.addView(col, Ui.wp(this, -2, 1, 10, 0, 8, 0));
        card.addView(top, Ui.lp(-1, -2));

        FlowLayout ops = new FlowLayout(this);
        if (idx > 0) {
            TextView up = Ui.pill(this, "↑", 0xFFF1F3F6, Ui.INK);
            up.setOnClickListener(v -> {
                sync();
                java.util.Collections.swap(profile.chain, idx, idx - 1);
                render();
            });
            ops.addView(up);
        }
        if (idx < profile.chain.size() - 1) {
            TextView down = Ui.pill(this, "↓", 0xFFF1F3F6, Ui.INK);
            down.setOnClickListener(v -> {
                sync();
                java.util.Collections.swap(profile.chain, idx, idx + 1);
                render();
            });
            ops.addView(down);
        }
        TextView edit = Ui.pill(this, "编辑这一跳", Ui.ACCENT_SOFT, Ui.ACCENT);
        edit.setOnClickListener(v -> {
            sync();
            openNode(idx);
        });
        ops.addView(edit);
        TextView del = Ui.pill(this, "移除", 0xFFFFF1F1, Ui.DANGER);
        del.setOnClickListener(v -> Ui.confirm(this, "移除这一跳",
                "只从这条链路里删掉，原配置本身不受影响。", new Runnable() {
                    public void run() {
                        sync();
                        if (profile.chain.size() <= 1) {
                            Ui.toast(EditActivity.this, "至少留一跳");
                            return;
                        }
                        profile.chain.remove(idx);
                        render();
                    }
                }));
        ops.addView(del);
        card.addView(ops, Ui.lp(this, -1, -2, 0, 8, 0, 0));
        form.addView(card, Ui.block(this, 0, 8));
    }

    private void addButtons() {
        /* 从已有配置：整行。它打开的是列表，手指目标要给够 */
        TextView from = Ui.pill(this, "＋ 从已有配置添加", Ui.NEUTRAL, Ui.INK);
        from.setOnClickListener(v -> {
            sync();
            pickExisting();
        });
        form.addView(from, Ui.lp(this, -1, -2, 0, 6, 0, 2));

        /* 新建 / 从链接新建：同一行，各占一半，不靠文字长短去决定换不换行 */
        LinearLayout pair = Ui.row(this);
        TextView fresh = Ui.pill(this, "＋ 添加新节点", Ui.ACCENT, Ui.WHITE);
        fresh.setOnClickListener(v -> {
            sync();
            startActivityForResult(nodeIntent(blank(Node.VLESS), true), REQ_NODE);
        });
        pair.addView(fresh, Ui.share(this, 0, 4));
        TextView link = Ui.pill(this, "＋ 从链接添加新节点", Ui.NEUTRAL, Ui.INK);
        link.setOnClickListener(v -> {
            sync();
            Ui.promptDialog(this, "粘贴分享链接（vless:// vmess:// trojan:// ss:// socks:// http://）",
                    "", new Ui.Sink() {
                        public void run(String text) {
                            addFromLink(text);
                        }
                    });
        });
        pair.addView(link, Ui.share(this, 4, 0));
        form.addView(pair, Ui.lp(this, -1, -2, 0, 8, 0, 0));

        form.addView(Ui.text(this, "链路的每一跳都是独立副本：在这里改节点不会动到它原来的配置。",
                11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 8));
    }

    private void pickExisting() {
        final List<Node> pool = new ArrayList<Node>();
        final List<String> labels = new ArrayList<String>();
        for (Profile p : Store.I.profiles) {
            for (Node n : p.chain) {
                pool.add(n);
                labels.add(p.name + " · " + n.title());
            }
        }
        if (pool.isEmpty()) {
            Ui.toast(this, "还没有任何配置可用");
            return;
        }
        Ui.choose(this, "从已有配置添加", labels.toArray(new String[0]), new Ui.Pick() {
            public void on(int i) {
                profile.chain.add(pool.get(i).copy());
                render();
            }
        });
    }

    private Intent nodeIntent(Node n, boolean inChain) {
        return new Intent(this, EditActivity.class)
                .putExtra(EXTRA_NODE, true)
                .putExtra(EXTRA_IN_CHAIN, inChain)
                .putExtra(EXTRA_NODE_JSON, n.toJson().toString());
    }

    private void openNode(int idx) {
        chainIndex = idx;
        startActivityForResult(nodeIntent(profile.chain.get(idx), true), REQ_NODE);
    }

    private void addFromLink(String text) {
        List<Profile> got = Links.parse(text);
        int add = 0;
        for (Profile p : got) {
            for (Node n : p.chain) {
                profile.chain.add(n.copy());
                add++;
            }
        }
        if (add == 0) {
            Ui.toast(this, "没解析出节点，检查链接");
            return;
        }
        render();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req != REQ_NODE || res != RESULT_OK || data == null) return;
        Node n = parseNode(data.getStringExtra(EXTRA_NODE_JSON));
        if (n == null) return;
        if (newNode) {
            setResult(RESULT_OK, new Intent().putExtra(EXTRA_NODE_JSON, n.toJson().toString()));
            finish();
            return;
        }
        if (chainIndex >= 0 && chainIndex < profile.chain.size()) profile.chain.set(chainIndex, n);
        else profile.chain.add(n);
        chainIndex = 0;
        render();
    }

    /* ------------------------------------------------------------------------ fields */

    private void field(LinearLayout parent, String label, String key, String value, boolean secret) {
        parent.addView(Ui.text(this, label, 11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 4));
        EditText e = Ui.field(this, "", value);
        if (secret) e.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        fields.put(key, e);
        parent.addView(e, Ui.lp(-1, -2));
    }

    /** 多行输入：JSON 这类会写很长、又需要看全的字段用。 */
    private void areaField(LinearLayout parent, String label, String key, String value, int lines) {
        parent.addView(Ui.text(this, label, 11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 8, 0, 4));
        EditText e = Ui.area(this, "", value, lines);
        fields.put(key, e);
        parent.addView(e, Ui.lp(-1, -2));
    }

    private interface BoolSink {
        void set(boolean on);
    }

    private void switchRow(LinearLayout parent, String label, boolean value, final BoolSink onChange) {
        final boolean[] state = {value};
        final TextView pill = Ui.pill(this, value ? "已开启" : "已关闭",
                value ? Ui.ACCENT_SOFT : Ui.NEUTRAL, value ? Ui.ACCENT : Ui.MUTED);
        LinearLayout r = Ui.row(this);
        r.addView(Ui.text(this, label, 13f, Ui.INK), Ui.wp(this, -2, 1, 0, 0, 8, 0));
        r.addView(pill);
        pill.setOnClickListener(v -> {
            state[0] = !state[0];
            pill.setText(state[0] ? "已开启" : "已关闭");
            pill.setBackground(Ui.chipBg(this, state[0] ? Ui.ACCENT_SOFT : Ui.NEUTRAL));
            pill.setTextColor(state[0] ? Ui.ACCENT : Ui.MUTED);
            onChange.set(state[0]);
        });
        parent.addView(r, Ui.lp(-1, -2));
    }

    private void uotRow(LinearLayout parent, final Node n) {
        final TextView pill = Ui.pill(this, n.uot ? "已开启" : "已关闭",
                n.uot ? Ui.ACCENT_SOFT : Ui.NEUTRAL, n.uot ? Ui.ACCENT : Ui.MUTED);
        LinearLayout r = Ui.row(this);
        r.addView(Ui.text(this, "UDP over TCP（uot）", 13f, Ui.INK), Ui.wp(this, -2, 1, 0, 0, 8, 0));
        r.addView(pill);
        pill.setOnClickListener(v -> {
            n.uot = !n.uot;
            pill.setText(n.uot ? "已开启" : "已关闭");
            pill.setBackground(Ui.chipBg(this, n.uot ? Ui.ACCENT_SOFT : Ui.NEUTRAL));
            pill.setTextColor(n.uot ? Ui.ACCENT : Ui.MUTED);
        });
        parent.addView(r, Ui.lp(-1, -2));
    }

    /* --------------------------------------------------------------------- save/sync */

    private void sync() {
        if (newNode) {
            Node n = node();
            apply(n);
            return;
        }
        EditText name = fields.get("__name");
        if (name != null) profile.name = name.getText().toString().trim();
        if (modeIdx != MODE_CHAIN) apply(node());
    }

    private void apply(Node n) {
        n.name = str("name", n.name);
        n.host = str("host", n.host).trim();
        n.port = num("port", n.port);
        n.uuid = str("uuid", n.uuid);
        n.password = str("password", n.password);
        n.method = str("method", n.method);
        n.user = str("user", n.user);
        n.alterId = num("alterId", n.alterId);
        n.vmessScy = str("vmessScy", n.vmessScy);
        n.vmessPcs = str("vmessPcs", n.vmessPcs);
        n.flow = str("flow", n.flow);
        n.security = str("security", n.security);
        n.sni = str("sni", n.sni);
        n.alpn = str("alpn", n.alpn);
        n.fp = str("fp", n.fp);
        n.pbk = str("pbk", n.pbk);
        n.sid = str("sid", n.sid);
        n.spx = str("spx", n.spx);
        n.net = str("net", n.net);
        n.headerType = str("headerType", n.headerType);
        n.quicSecurity = str("quicSecurity", n.quicSecurity);
        n.quicKey = str("quicKey", n.quicKey).trim();
        n.encryption = str("encryption", n.encryption).trim();
        if (n.encryption.length() == 0) n.encryption = "none";
        n.grpcMode = str("grpcMode", n.grpcMode);
        n.xhttpMode = str("xhttpMode", n.xhttpMode);
        n.xhttpExtra = str("xhttpExtra", n.xhttpExtra).trim();
        n.kcpSeed = str("kcpSeed", n.kcpSeed);
        n.kcpMtu = num("kcpMtu", n.kcpMtu);
        n.kcpTti = num("kcpTti", n.kcpTti);
        n.ech = str("ech", n.ech).trim();
        n.verifyPeer = str("verifyPeer", n.verifyPeer).trim();
        n.pinnedCA = str("pinnedCA", n.pinnedCA).trim();
        n.mldsa = str("mldsa", n.mldsa).trim();
        n.finalMask = str("finalMask", n.finalMask).trim();
        n.path = str("path", n.path);
        n.hostHdr = str("hostHdr", n.hostHdr);
        n.serviceName = str("serviceName", n.serviceName);
        n.ini = str("ini", n.ini);
    }

    private String str(String key, String def) {
        if (picked.containsKey(key)) {
            String v = picked.get(key);
            return v == null ? def : v;
        }
        EditText e = fields.get(key);
        return e == null ? def : e.getText().toString();
    }

    private int num(String key, int def) {
        try {
            return Integer.parseInt(str(key, String.valueOf(def)).trim());
        } catch (Exception e) {
            return def;
        }
    }

    private void saveAll() {
        if (newNode) {
            Node n = node();
            apply(n);
            String bad = validate(n);
            if (bad != null) {
                Ui.toast(this, bad);
                return;
            }
            setResult(RESULT_OK, new Intent().putExtra(EXTRA_NODE_JSON, n.toJson().toString()));
            finish();
            return;
        }
        sync();
        if (modeIdx == MODE_CHAIN && profile.chain.isEmpty()) {
            Ui.toast(this, "链路还是空的：先加一跳");
            return;
        }
        /* 名字留空或还是默认值时才自动起名，用户自己写的一个字都不改 */
        if (defaultName(profile.name)) profile.name = autoName(profile);
        if (modeIdx != MODE_CHAIN) {
            String bad = validate(node());
            if (bad != null) {
                Ui.toast(this, bad);
                return;
            }
        }
        profile.updated = (int) (System.currentTimeMillis() / 1000L);
        if (isNew || original == null) {
            Store.I.add(profile);
        } else {
            original.takeFrom(profile);
            original.updated = profile.updated;
            Store.I.save();
        }
        if (Control.running()) Control.disconnectSoon(this);
        setResult(RESULT_OK);
        finish();
    }

    /** 内网/本机地址判定统一放 Node 里，启动日志那边也要用同一套。 */
    static boolean privateHost(String host) {
        return Node.isPrivateHost(host);
    }

    /** 每种协议只校验它真正必需的字段，避免把可选字段（SOCKS 用户名等）误判成错误。 */
    private String validate(Node n) {
        if (n == null) return "没有可保存的节点";
        if (Node.INJECT.equals(n.type)) {
            if (!inChain && profile.chain.size() == 1 && n.udpNode != null && n.udpViaInject) {
                if (!Node.udpOverTcp(n.udpNode)) {
                    return "该 UDP 节点不能经注入网关，请改「直连该节点」或换 VLESS / VMess";
                }
                if ("kcp".equals(n.udpNode.net) || "quic".equals(n.udpNode.net)) {
                    return "该 UDP 节点是 " + n.udpNode.net + " 传输，无法经注入网关，请改直连";
                }
            }
            return null;
        }
        if (n.host == null || n.host.trim().length() == 0) return "地址不能为空";
        if (n.port < 1 || n.port > 65535) return "端口必须在 1–65535";
        if ((Node.VLESS.equals(n.type) || Node.VMESS.equals(n.type))
                && (n.uuid == null || n.uuid.trim().length() == 0)) return "UUID 不能为空";
        if ((Node.TROJAN.equals(n.type) || Node.SS.equals(n.type))
                && (n.password == null || n.password.length() == 0)) return "密码不能为空";
        return null;
    }

    @Override
    public void onBackPressed() {
        leave();
    }

    /** 返回 = 放弃：动过才问，没动直接走 */
    private void leave() {
        if (!dirty()) {
            finish();
            return;
        }
        Ui.confirm(this, "放弃这次编辑？", "还没点保存，返回就丢掉了。", new Runnable() {
            public void run() {
                finish();
            }
        });
    }

    private boolean dirty() {
        return born != null && !born.equals(profile.toJson().toString());
    }
}
