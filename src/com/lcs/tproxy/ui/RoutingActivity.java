package com.lcs.tproxy.ui;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Rule;
import com.lcs.tproxy.model.Store;

/** Routing rules: preset + ordered user rules, v2rayNG style. */
public class RoutingActivity extends Activity {

    public static final String EXTRA_PROFILE = "profile";
    /** Store 里的真身：只有点「保存」才会被草稿覆盖 */
    private Profile src;
    /** 草稿：页面上改的全在它身上，返回就丢 */
    private Profile profile;
    private boolean dirty;
    private LinearLayout box;
    private TextView presetView;
    /** 下拉栏里那行文字：build() 建一次，选完要就地刷新，不能等重进页面 */
    private TextView v6View;
    private TextView udpView, quicView, dnsView;

    public static void open(Context c, String profileId) {
        Intent i = new Intent(c, RoutingActivity.class);
        i.putExtra(EXTRA_PROFILE, profileId);
        c.startActivity(i);
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Ui.lightStatus(this);
        String pid = getIntent().getStringExtra(EXTRA_PROFILE);
        for (Profile p : Store.I.profiles) if (p.id.equals(pid)) src = p;
        if (src == null) {
            finish();
            return;
        }
        profile = src.draft();
        setContentView(build());
        render();
    }

    private View build() {
        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.BG);
        LinearLayout bar = Ui.row(this);
        bar.setBackgroundColor(Ui.WHITE);
        int p = Ui.dp(this, 16);
        bar.setPadding(p, Ui.dp(this, 14), p, Ui.dp(this, 14));
        TextView back = Ui.text(this, "‹ 返回", 15f, Ui.ACCENT);
        back.setOnClickListener(v -> leave());
        bar.addView(back);
        TextView title = Ui.text(this, "路由", 17f, Ui.INK);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setGravity(android.view.Gravity.CENTER);
        bar.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView done = Ui.text(this, "保存", 15f, Ui.ACCENT);
        done.setOnClickListener(v -> commit());
        bar.addView(done);
        root.addView(bar);

        LinearLayout content = Ui.column(this);
        LinearLayout preset = Ui.card(this);
        preset.addView(Ui.label(this, "预设"));
        presetView = Ui.text(this, "", 15f, Ui.INK);
        presetView.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 6));
        preset.addView(presetView);
        preset.addView(Ui.text(this, "预设规则会先于下面的自定义规则生效。", 11.5f, Ui.MUTED));
        preset.setOnClickListener(v -> Ui.choose(this, "路由预设", new String[]{
                "全部走代理", "绕过大陆", "仅局域网直连"}, i -> {
            profile.preset = i == 0 ? Profile.P_GLOBAL : i == 1 ? Profile.P_BYPASS_CN : Profile.P_BYPASS_LAN;
            dirty = true;
            render();
        }));
        content.addView(preset, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, Ui.dp(this, 10)));

        LinearLayout v6 = Ui.card(this);
        v6.addView(Ui.label(this, "IPv6 怎么走"));
        v6View = Ui.text(this, v6Name(profile.v6), 14.5f, Ui.INK);
        v6View.setSingleLine(true);
        LinearLayout v6box = Ui.row(this);
        v6box.setBackground(Ui.roundStroke(0xFFFBFCFD, Ui.dp(this, 10), Ui.LINE, 1));
        v6box.setPadding(Ui.dp(this, 12), Ui.dp(this, 11), Ui.dp(this, 12), Ui.dp(this, 11));
        v6box.addView(v6View, Ui.wp(this, -2, 1, 0, 0, 8, 0));
        v6box.addView(Ui.text(this, "▾", 12f, Ui.MUTED));
        v6box.setOnClickListener(v -> Ui.choose(this, "IPv6 怎么走", V6_NAMES, i -> {
            profile.v6 = V6_KEYS[i];
            dirty = true;
            render();
        }));
        v6.addView(v6box, Ui.lp(this, -1, -2, 0, 8, 0, 0));

        v6.addView(Ui.text(this, V6_HELP, 11.5f, Ui.MUTED),
                Ui.lp(this, -1, -2, 0, 10, 0, 8));
        v6.addView(Ui.text(this, APN_HELP, 11.5f, Ui.MUTED),
                Ui.lp(this, -1, -2, 0, 8, 0, 0));
        content.addView(v6, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, Ui.dp(this, 10)));

        LinearLayout traffic = Ui.card(this);
        traffic.addView(Ui.label(this, "UDP / QUIC / DNS"));
        traffic.addView(Ui.text(this,
                "三态：禁用=丢包；代理=进 xray；直连=明确允许走物理网络。"
                        + "默认 UDP 与 QUIC 禁用、DNS 代理，不会偷跑。\n"
                        + "代理是否可用取决于链路首跳是否支持 UDP/DoH；失败会明确报错，"
                        + "不会自动改成直连。\n"
                        + "DNS 代理失败时请明确选 DNS 直连，或把注入网关写成 IP。", 11.5f, Ui.MUTED));
        udpView = Ui.text(this, "", 13.5f, Ui.INK);
        quicView = Ui.text(this, "", 13.5f, Ui.INK);
        dnsView = Ui.text(this, "", 13.5f, Ui.INK);
        traffic.addView(policyRow("其他 UDP", udpView, POLICY_KEYS, UDP_NAMES, v -> profile.udpPolicy = v));
        traffic.addView(policyRow("QUIC / UDP 443", quicView, POLICY_KEYS, QUIC_NAMES, v -> profile.quicPolicy = v));
        traffic.addView(policyRow("DNS / 53", dnsView, POLICY_KEYS, DNS_NAMES, v -> profile.dnsPolicy = v));
        content.addView(traffic, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, Ui.dp(this, 10)));

        box = Ui.column(this);
        content.addView(box);

        LinearLayout ops = Ui.row(this);
        ops.setPadding(0, Ui.dp(this, 12), 0, 0);
        TextView add = Ui.pill(this, "＋ 添加规则", Ui.ACCENT, Ui.WHITE);
        add.setOnClickListener(v -> addRule(null));
        TextView imp = Ui.pill(this, "从配置导入", 0xFFF1F3F6, Ui.INK);
        imp.setOnClickListener(v -> importRules());
        ops.addView(add, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        LinearLayout.LayoutParams lm = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lm.leftMargin = Ui.dp(this, 10);
        ops.addView(imp, lm);
        content.addView(ops);

        root.addView(Ui.page(this, content), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    /** 把草稿合回真身并落盘，然后关页 */
    private void commit() {
        src.takeFrom(profile);
        Store.I.save();
        dirty = false;
        com.lcs.tproxy.core.Control.disconnectSoon(this);
        Ui.toast(this, "路由已保存，运行配置已断开");
        finish();
    }

    /** 返回 = 放弃：脏了先问一句，不脏直接走 */
    private void leave() {
        if (!dirty) {
            finish();
            return;
        }
        Ui.confirm(this, "放弃这次修改？", "路由里改的东西还没保存，返回就丢掉了。", new Runnable() {
            public void run() {
                finish();
            }
        });
    }

    @Override
    public void onBackPressed() {
        leave();
    }

    private void render() {
        String p = profile.preset;
        presetView.setText(Profile.P_GLOBAL.equals(p) ? "全部走代理"
                : Profile.P_BYPASS_CN.equals(p) ? "绕过大陆" : "仅局域网直连");
        if (v6View != null) v6View.setText(v6Name(profile.v6));
        if (udpView != null) udpView.setText(policyText(profile.udpPolicy, UDP_NAMES, true));
        if (quicView != null) quicView.setText(policyText(profile.quicPolicy, QUIC_NAMES, true));
        if (dnsView != null) dnsView.setText(policyText(profile.dnsPolicy, DNS_NAMES, false));
        box.removeAllViews();
        if (profile.rules.isEmpty()) {
            LinearLayout empty = Ui.card(this);
            empty.addView(Ui.text(this, "还没有自定义规则", 13f, Ui.MUTED));
            empty.addView(Ui.text(this, "例如：域名后缀 google.com → 代理；GeoIP cn → 直连。", 11.5f, Ui.MUTED));
            box.addView(empty);
            return;
        }
        for (int i = 0; i < profile.rules.size(); i++) {
            final int idx = i;
            final Rule r = profile.rules.get(i);
            LinearLayout card = Ui.card(this);
            LinearLayout.LayoutParams cp = Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, Ui.dp(this, 8));
            card.setLayoutParams(cp);
            LinearLayout top = Ui.row(this);
            TextView act = Ui.pill(this, Rule.actionLabel(r.action),
                    Rule.A_DIRECT.equals(r.action) ? 0xFFEAF7EF
                            : Rule.A_BLOCK.equals(r.action) ? 0xFFFFEFF0 : Ui.ACCENT_SOFT,
                    Rule.A_DIRECT.equals(r.action) ? Ui.OK
                            : Rule.A_BLOCK.equals(r.action) ? Ui.DANGER : Ui.ACCENT);
            act.setTextSize(11f);
            top.addView(act);
            TextView body = Ui.text(this, r.label(), 13f, Ui.INK);
            LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            blp.leftMargin = Ui.dp(this, 10);
            top.addView(body, blp);
            TextView up = Ui.pill(this, "↑", 0xFFF1F3F6, Ui.INK);
            TextView del = Ui.pill(this, "✕", 0xFFFFEFF0, Ui.DANGER);
            top.addView(up);
            top.addView(del);
            card.addView(top);
            up.setOnClickListener(v -> {
                if (idx == 0) return;
                Rule x = profile.rules.remove(idx);
                profile.rules.add(idx - 1, x);
                dirty = true;
                render();
            });
            del.setOnClickListener(v -> {
                profile.rules.remove(idx);
                dirty = true;
                render();
            });
            card.setOnClickListener(v -> addRule(r));
            box.addView(card);
        }
    }

    /** null = create, non-null = edit in place */
    private void addRule(final Rule editing) {
        final String[] fields = {Rule.F_DOMAIN_SUFFIX, Rule.F_DOMAIN, Rule.F_DOMAIN_KEYWORD,
                Rule.F_DOMAIN_REGEX, Rule.F_GEOSITE, Rule.F_IP, Rule.F_GEOIP, Rule.F_PORT,
                Rule.F_PROCESS, Rule.F_NETWORK};
        final String[] labels = new String[fields.length];
        for (int i = 0; i < fields.length; i++) labels[i] = Rule.fieldLabel(fields[i]);
        Ui.choose(this, "匹配类型", labels, fi -> {
            final String field = fields[fi];
            Ui.inputDialog(this, Rule.fieldLabel(field) + " 的值",
                    editing == null ? "" : editing.value, value -> {
                        if (value.trim().isEmpty()) return;
                        final Rule r = editing == null ? new Rule() : editing;
                        r.field = field;
                        r.value = value.trim();
                        Ui.choose(this, "动作", new String[]{"代理", "直连", "拦截"}, ai -> {
                            r.action = ai == 0 ? Rule.A_PROXY : ai == 1 ? Rule.A_DIRECT : Rule.A_BLOCK;
                            if (editing == null) profile.rules.add(r);
                            dirty = true;
                            render();
                        });
                    });
        });
    }

    private void importRules() {
        Ui.promptDialog(this, "粘贴 v2ray/xray 配置以导入路由", "", text -> {
            Profile p = com.lcs.tproxy.link.Links.fromJsonConfig(text);
            if (p == null || p.rules.isEmpty()) {
                Ui.toast(this, "没有解析到规则");
                return;
            }
            profile.rules.addAll(p.rules);
            profile.preset = Profile.P_NONE;
            dirty = true;
            render();
            Ui.toast(this, "导入 " + p.rules.size() + " 条规则");
        });
    }

    private interface PolicySet {
        void set(String value);
    }

    private View policyRow(String label, TextView value, String[] keys, String[] names, PolicySet set) {
        LinearLayout row = Ui.row(this);
        row.setPadding(0, Ui.dp(this, 8), 0, 0);
        row.addView(Ui.text(this, label, 13f, Ui.INK),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        value.setPadding(Ui.dp(this, 8), Ui.dp(this, 4), Ui.dp(this, 8), Ui.dp(this, 4));
        value.setBackground(Ui.roundStroke(0xFFFBFCFD, Ui.dp(this, 9), Ui.LINE, 1));
        value.setOnClickListener(v -> Ui.choose(this, label, names, i -> {
            set.set(keys[i]);
            dirty = true;
            render();
        }));
        LinearLayout.LayoutParams vlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        vlp.setMargins(Ui.dp(this, 8), 0, 0, 0);
        row.addView(value, vlp);
        return row;
    }

    private String policyText(String key, String[] names, boolean udp) {
        int i = 0;
        while (i < POLICY_KEYS.length && !POLICY_KEYS[i].equals(key)) i++;
        if (i >= POLICY_KEYS.length) return "未知（按禁用）";
        return names[i];
    }

    static final String[] POLICY_KEYS = {Profile.UDP_BLOCK, Profile.UDP_PROXY, Profile.UDP_DIRECT};
    static final String[] UDP_NAMES = {"禁用（DROP）", "代理（TPROXY）", "直连（会跑真实流量）"};
    static final String[] QUIC_NAMES = {"禁用（DROP）", "代理（TPROXY）", "直连（会跑真实流量）"};
    static final String[] DNS_NAMES = {"禁用（DROP）", "代理（xray 解析）", "直连（系统 DNS）"};

    /** IPv6 三选一：和 VPN / 热点两种模式共用同一套语义，不再有第二个开关 */
    static final String[] V6_KEYS = {Profile.V6_PROXY, Profile.V6_BLOCK, Profile.V6_DIRECT};
    static final String[] V6_NAMES = {
            "直送链路（最后一跳有 IPv6 出口）",
            "送入黑洞（最后一跳没有 IPv6）",
            "完全不接管（v6 直连，会漏）"};

    static String v6Name(String key) {
        for (int i = 0; i < V6_KEYS.length; i++) if (V6_KEYS[i].equals(key)) return V6_NAMES[i];
        return V6_NAMES[0];
    }

    static final String V6_HELP =
            "直送链路：v6 和 v4 一样进隧道。最后一跳（链路里唯一会真正拨号到目标的那一跳）有 v6 出口时，"
            .concat("图片 / 直播那些双栈 CDN 的 v6 分片才走得通；它没有 v6 时这些连接会失败，但不会漏真实地址。\n\n")
            .concat("送入黑洞：v6 全部丢掉。热点模式直接在内核 DROP（SYN 没人应答，应用约 250ms 就回落 v4）；")
            .concat("VPN 模式走 xray 黑洞。纯 v6 的应用（部分直播 / 图片源）会失效。\n\n")
            .concat("完全不接管：v6 直接走系统网络，真实地址会暴露给对端 —— 这是旧版代理的做法，")
            .concat("只在明确不要防漏时选。");

    static final String APN_HELP =
            "更彻底的办法在系统里：设置 → 移动网络 → 接入点(APN) → 把「APN 协议」和「APN 漫游协议」"
            .concat("都改成 IPv4。这样手机和它带的热点设备都拿不到 v6 地址，应用一拨号就收到 ENETUNREACH，")
            .concat("立刻回落 v4 —— 比黑洞更干净，连重试都不会有。代价是只对蜂窝生效，")
            .concat("WiFi 下 v6 由路由器发，得在路由器上关。");

}
