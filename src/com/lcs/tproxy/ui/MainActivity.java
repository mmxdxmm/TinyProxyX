package com.lcs.tproxy.ui;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import java.net.Socket;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.lcs.tproxy.core.Control;
import com.lcs.tproxy.core.Engine;
import com.lcs.tproxy.link.Links;
import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity implements Control.Watcher {

    private LinearLayout content;
    private LinearLayout listBox;
    private TextView statusTitle;
    private TextView statusSub;
    private View dot;
    private TextView startBtn;
    private TextView modeChip;
    private final Set<String> expanded = new HashSet<String>();
    private int reqVpn = 1001;
    private EditText searchField;
    private String query = "";
    private boolean pendingStart = false;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Store.I.load(this);
        Ui.lightStatus(this);
        buildUi();
        Control.add(this);
        Control.sweepStaleRoot(this);
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            try {
                if (checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                        != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 4001);
                }
            } catch (Exception ignored) {
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    @Override
    protected void onDestroy() {
        Control.remove(this);
        super.onDestroy();
    }

    @Override
    public void onChanged() {
        runOnUiThread(new Runnable() {
            public void run() {
                refresh();
            }
        });
    }

    /* ------------------------------------------------------------------ shell */

    private void buildUi() {
        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.BG);

        LinearLayout header = Ui.row(this);
        header.setBackgroundColor(Ui.WHITE);
        int hp = Ui.dp(this, 16);
        header.setPadding(hp, Ui.dp(this, 14), hp, Ui.dp(this, 12));
        LinearLayout titles = Ui.column(this);
        TextView t = Ui.text(this, "TinyProxy X", 20f, Ui.INK);
        t.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        titles.addView(t);
        titles.addView(Ui.text(this, "多协议链路 · Xray 内核", 11.5f, Ui.MUTED));
        header.addView(titles, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView rootBtn = Ui.pill(this, "热点", Ui.ACCENT_SOFT, Ui.ACCENT);
        TextView setBtn = Ui.pill(this, "设置", 0xFFF1F3F6, Ui.INK);
        LinearLayout.LayoutParams rm = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rm.rightMargin = Ui.dp(this, 8);
        header.addView(rootBtn, rm);
        header.addView(setBtn);
        root.addView(header, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        content = Ui.column(this);
        ScrollView sv = Ui.page(this, content);

        // ---- status card
        LinearLayout card = Ui.card(this);
        LinearLayout top = Ui.row(this);
        dot = new View(this);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(Ui.dp(this, 10), Ui.dp(this, 10));
        dlp.rightMargin = Ui.dp(this, 8);
        dot.setBackgroundDrawable(Ui.round(Ui.MUTED, Ui.dp(this, 5)));
        top.addView(dot, dlp);
        LinearLayout texts = Ui.column(this);
        statusTitle = Ui.text(this, "未连接", 17f, Ui.INK);
        statusTitle.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        statusSub = Ui.text(this, "点击下方按钮开始", 12f, Ui.MUTED);
        texts.addView(statusTitle);
        texts.addView(statusSub);
        top.addView(texts, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        modeChip = Ui.pill(this, "VPN", Ui.ACCENT_SOFT, Ui.ACCENT);
        top.addView(modeChip);
        card.addView(top);

        /* 链路芯片用 FlowLayout：三跳以上时普通 LinearLayout 会横向顶出屏幕，
         * 后面的芯片看不见也点不到。 */
        FlowLayout chainBox = new FlowLayout(this, Ui.dp(this, 6), Ui.dp(this, 6));
        chainBox.setPadding(0, Ui.dp(this, 12), 0, 0);
        chainBox.setId(9001);
        card.addView(chainBox);

        startBtn = Ui.pill(this, "启 动", Ui.ACCENT, Ui.WHITE);
        startBtn.setTextSize(15f);
        startBtn.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 48));
        slp.topMargin = Ui.dp(this, 14);
        card.addView(startBtn, slp);

        LinearLayout links = Ui.row(this);
        links.setPadding(0, Ui.dp(this, 10), 0, 0);
        TextView logBtn = Ui.text(this, "运行日志", 12.5f, Ui.ACCENT);
        TextView cfgBtn = Ui.text(this, "预览配置", 12.5f, Ui.ACCENT);
        links.addView(logBtn);
        LinearLayout.LayoutParams lm = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lm.leftMargin = Ui.dp(this, 18);
        links.addView(cfgBtn, lm);
        card.addView(links);

        content.addView(card, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        // ---- profile section
        LinearLayout secRow = Ui.row(this);
        secRow.setPadding(Ui.dp(this, 4), Ui.dp(this, 18), Ui.dp(this, 4), Ui.dp(this, 8));
        TextView sec = Ui.text(this, "配置", 13f, Ui.MUTED);
        sec.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        secRow.addView(sec, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        content.addView(secRow);

        searchField = Ui.field(this, "搜索配置 / 服务器地址", "");
        searchField.setSingleLine(true);
        LinearLayout.LayoutParams sfp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sfp.bottomMargin = Ui.dp(this, 8);
        searchField.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            public void onTextChanged(CharSequence s, int a, int b, int c) {
            }

            public void afterTextChanged(android.text.Editable s) {
                query = s.toString().trim().toLowerCase();
                renderList();
            }
        });
        content.addView(searchField, sfp);

        listBox = Ui.column(this);
        content.addView(listBox);

        LinearLayout actions = Ui.row(this);
        actions.setPadding(0, Ui.dp(this, 12), 0, 0);
        TextView add = Ui.pill(this, "＋ 新建配置", Ui.WHITE, Ui.ACCENT);
        add.setBackgroundDrawable(Ui.roundStroke(Ui.WHITE, Ui.dp(this, 22), Ui.ACCENT, Ui.dp(this, 1)));
        TextView imp = Ui.pill(this, "导入链接 / 配置", Ui.WHITE, Ui.INK);
        imp.setBackgroundDrawable(Ui.roundStroke(Ui.WHITE, Ui.dp(this, 22), Ui.LINE, Ui.dp(this, 1)));
        actions.addView(add, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        LinearLayout.LayoutParams im = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        im.leftMargin = Ui.dp(this, 10);
        actions.addView(imp, im);
        content.addView(actions);

        root.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        startBtn.setOnClickListener(v -> toggle());
        modeChip.setOnClickListener(v -> {
            Ui.choose(this, "运行模式", new String[]{"VPN 模式（无需 root）", "热点模式（root · 也能共享给热点设备）"},
                    i -> {
                        String next = i == 0 ? "vpn" : "root";
                        boolean changed = !next.equals(Store.I.settings.mode);
                        Store.I.settings.mode = next;
                        Store.I.save();
                        refresh();
                        if (i > 0 && !com.lcs.tproxy.root.Root.hasRoot()) {
                            Ui.info(this, "没有 root", "检测不到 root 授权，热点模式将无法启动。");
                        }
                        /* 模式改了只断开，不自动重连：以前是 stop→start，
                         * 旧 Service 还在收 tun 时新的又去抢 VpnService，会闪退。 */
                        if (changed && Control.running()) {
                            Control.disconnectSoon(this);
                            Ui.toast(this, "已断开当前连接，点主页按钮按新模重连");
                        }
                    });
        });
        logBtn.setOnClickListener(v -> startActivity(new Intent(this, LogActivity.class)));
        cfgBtn.setOnClickListener(v -> Ui.info(this, "生成的 xray 配置",
                Engine.I.configText().length() == 0 ? "尚未生成" : Engine.I.configText()));
        setBtn.setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        rootBtn.setOnClickListener(v -> startActivity(new Intent(this, RootActivity.class)));
        add.setOnClickListener(v -> createProfile());
        imp.setOnClickListener(v -> importDialog());
    }

    /* ------------------------------------------------------------------ state */

    private void refresh() {
        boolean running = Engine.I.isRunning();
        boolean has = Store.I.selected() != null && !Store.I.selected().chain.isEmpty();
        String mode = Store.I.settings.mode;
        modeChip.setText(mode.equals("vpn") ? "VPN" : "热点");

        boolean stopping = "stopping".equals(Control.state);
        if (stopping) {
            /* 停止要等 xray 退出、root 规则回滚，热点模式下要几秒；状态栏又可能被
             * 报错占着，所以按钮自己说明"正在停止"，别让人以为没点上。 */
            dot.setBackgroundDrawable(Ui.round(Ui.WARN, Ui.dp(this, 5)));
            statusTitle.setText("正在停止");
            statusSub.setText(Control.message.length() > 0 ? Control.message : "正在断开并清理");
            startBtn.setText("正在停止…");
            startBtn.setBackgroundDrawable(Ui.round(0xFFF2F4F7, Ui.dp(this, 24)));
            startBtn.setTextColor(Ui.MUTED);
        } else if (running) {
            dot.setBackgroundDrawable(Ui.round(Ui.OK, Ui.dp(this, 5)));
            statusTitle.setText("已连接");
            statusSub.setText(Control.message.length() > 0 ? Control.message : "运行中");
            startBtn.setText("停 止");
            startBtn.setBackgroundDrawable(Ui.round(0xFFFFEFF0, Ui.dp(this, 24)));
            startBtn.setTextColor(Ui.DANGER);
        } else {
            dot.setBackgroundDrawable(Ui.round(has ? Ui.WARN : Ui.MUTED, Ui.dp(this, 5)));
            statusTitle.setText(Control.state.equals("starting") ? "正在连接" : "未连接");
            statusSub.setText(Control.message.length() > 0 ? Control.message
                    : (has ? "已选择 " + Store.I.selected().name : "还没有配置"));
            startBtn.setText(Control.busy() ? "连接中…" : "启 动");
            startBtn.setBackgroundDrawable(Ui.round(Ui.ACCENT, Ui.dp(this, 24)));
            startBtn.setTextColor(Ui.WHITE);
        }
        String inj = running ? Engine.I.injectStatus() : null;
        if (inj != null) {
            statusSub.setText(inj);
            statusSub.setTextColor(Ui.DANGER);
        } else {
            statusSub.setTextColor(Ui.MUTED);
        }
        renderChain();
        renderList();
    }

    private void renderChain() {
        View box = findViewById(9001);
        if (!(box instanceof android.view.ViewGroup)) return;
        android.view.ViewGroup group = (android.view.ViewGroup) box;
        group.removeAllViews();
        Profile p = Store.I.selected();
        List<String> parts = new ArrayList<String>();
        parts.add("本机");
        if (p != null) for (Node n : p.chain) parts.add(shortName(n));
        parts.add("目标");
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) {
                TextView arrow = Ui.text(this, "›", 12f, 0xFFC3CAD4);
                arrow.setPadding(Ui.dp(this, 1), 0, Ui.dp(this, 1), 0);
                group.addView(arrow);
            }
            TextView chip = Ui.text(this, parts.get(i), 12f,
                    i == 0 || i == parts.size() - 1 ? Ui.MUTED : Ui.ACCENT);
            chip.setSingleLine(true);
            chip.setEllipsize(android.text.TextUtils.TruncateAt.END);
            chip.setBackgroundDrawable(Ui.round(i == 0 || i == parts.size() - 1
                    ? 0xFFF2F4F7 : Ui.ACCENT_SOFT, Ui.dp(this, 8)));
            chip.setPadding(Ui.dp(this, 8), Ui.dp(this, 4), Ui.dp(this, 8), Ui.dp(this, 4));
            group.addView(chip);
        }
    }

    private String shortName(Node n) {
        if (n.name != null && n.name.length() > 0) return n.name;
        return n.type.toUpperCase();
    }

    private void renderList() {
        listBox.removeAllViews();
        for (final Profile p : Store.I.profiles) {
            if (query.length() > 0) {
                String hay = (p.name + " " + p.chainSummary() + " " + p.desc()).toLowerCase();
                if (!hay.contains(query)) continue;
            }
            boolean sel = p.id.equals(Store.I.selectedId);
            LinearLayout card = Ui.card(this);
            LinearLayout.LayoutParams cp = Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, Ui.dp(this, 10));
            card.setLayoutParams(cp);
            if (sel) card.setBackgroundDrawable(Ui.roundStroke(Ui.WHITE, Ui.dp(this, 16), Ui.ACCENT, Ui.dp(this, 1)));

            LinearLayout top = Ui.row(this);
            TextView badge = Ui.text(this, badgeOf(p), 12f, sel ? Ui.WHITE : Ui.ACCENT);
            badge.setGravity(Gravity.CENTER);
            badge.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            badge.setBackgroundDrawable(Ui.round(sel ? Ui.ACCENT : Ui.ACCENT_SOFT, Ui.dp(this, 9)));
            LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(Ui.dp(this, 34), Ui.dp(this, 34));
            blp.rightMargin = Ui.dp(this, 10);
            top.addView(badge, blp);

            LinearLayout names = Ui.column(this);
            TextView nm = Ui.text(this, p.name, 15.5f, Ui.INK);
            nm.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            names.addView(nm);
            names.addView(Ui.text(this, p.desc(), 11.5f, Ui.MUTED));
            top.addView(names, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

            TextView chev = Ui.pill(this, expanded.contains(p.id) ? "收起" : "展开",
                    Ui.WHITE, expanded.contains(p.id) ? Ui.ACCENT : Ui.MUTED);
            chev.setTextSize(12f);
            chev.setBackgroundDrawable(Ui.roundStroke(Ui.WHITE, Ui.dp(this, 22),
                    expanded.contains(p.id) ? Ui.ACCENT : Ui.LINE, Ui.dp(this, 1)));
            top.addView(chev);
            card.addView(top);

            if (expanded.contains(p.id)) card.addView(quickEditor(p));

            card.setOnClickListener(v -> selectProfile(p));
            chev.setOnClickListener(v -> {
                if (expanded.contains(p.id)) expanded.remove(p.id);
                else expanded.add(p.id);
                renderList();
            });
            listBox.addView(card);
        }
    }

    /** 运行中点另一张配置卡：先问，再决定要不要断线重连（防止误触把链路重启）。 */
    private void selectProfile(final Profile p) {
        if (p.id.equals(Store.I.selectedId)) {
            expanded.add(p.id);
            renderList();
            return;
        }
        if (!Control.running()) {
            Store.I.select(p.id);
            refresh();
            return;
        }
        Ui.confirm(this, "切换配置", "当前正在运行，切到「" + p.name + "」会断开当前连接，需要手动重连。",
                new Runnable() {
            public void run() {
                Store.I.select(p.id);
                refresh();
                Control.disconnect(MainActivity.this);
            }
        });
    }

    private static final String[] BADGE = {"VL", "VM", "TR", "SS", "S5", "HT", "IN", "PX"};

    private String badgeOf(Profile p) {
        if (p.chain.isEmpty()) return "空";
        return BADGE[p.chain.get(p.chain.size() - 1).kind()];
    }

    /** inline, interactive quick edit -- the "点进去就能改" surface */
    private View quickEditor(final Profile p) {
        LinearLayout box = Ui.column(this);
        box.setPadding(0, Ui.dp(this, 12), 0, 0);
        box.addView(Ui.divider(this));
        LinearLayout pad = Ui.column(this);
        pad.setPadding(0, Ui.dp(this, 12), 0, 0);
        box.addView(pad);

        final EditText name = Ui.field(this, "配置名称", p.name);
        pad.addView(labelRow("名称", name));

        Node exit = p.exit();
        if (exit != null && Node.INJECT.equals(exit.type)) {
            pad.addView(injectSummary(exit));
            pad.addView(opsFor(p));
            return box;
        }
        if (exit != null) {
            final EditText host = Ui.field(this, "服务器地址", exit.host);
            final EditText port = Ui.field(this, "端口", String.valueOf(exit.port));
            final EditText secret = Ui.field(this,
                    Node.SOCKS.equals(exit.type) || Node.HTTP.equals(exit.type) ? "用户名" : "密码 / UUID",
                    Node.SOCKS.equals(exit.type) || Node.HTTP.equals(exit.type) ? exit.user : passwordOf(exit));
            pad.addView(labelRow("地址", host));
            pad.addView(labelRow("端口", port));
            pad.addView(labelRow("凭据", secret));

            LinearLayout ops = Ui.row(this);
            TextView save = Ui.pill(this, "保存", Ui.ACCENT, Ui.WHITE);
            ops.addView(save);
            save.setOnClickListener(v -> {
                p.name = name.getText().toString().trim();
                exit.host = host.getText().toString().trim();
                try {
                    exit.port = Integer.parseInt(port.getText().toString().trim());
                } catch (Exception ignored) {
                }
                String s = secret.getText().toString();
                if (Node.SOCKS.equals(exit.type) || Node.HTTP.equals(exit.type)) exit.user = s;
                else setPassword(exit, s);
                Store.I.save();
                if (Control.running()) {
                    Control.disconnectSoon(MainActivity.this);
                    Ui.toast(this, "已保存，已断开连接（点主页按钮重连）");
                } else {
                    Ui.toast(this, "已保存");
                }
                refresh();
            });
            LinearLayout.LayoutParams sm = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            sm.rightMargin = Ui.dp(this, 8);
            save.setLayoutParams(sm);
            pad.addView(ops);
        }

        pad.addView(opsFor(p));
        return box;
    }

    /** 编辑/路由/测速/分享/删除 —— 配置卡和注入卡共用 */
    private FlowLayout opsFor(final Profile p) {
        FlowLayout ops = new FlowLayout(this, Ui.dp(this, 8), Ui.dp(this, 8));
        ops.setPadding(0, Ui.dp(this, 12), 0, 0);
        TextView edit = Ui.pill(this, "编辑配置", Ui.WHITE, Ui.ACCENT);
        edit.setTextSize(12.5f);
        edit.setBackgroundDrawable(Ui.roundStroke(Ui.WHITE, Ui.dp(this, 22), Ui.ACCENT, Ui.dp(this, 1)));
        edit.setOnClickListener(v -> EditActivity.open(this, p.id));
        ops.addView(edit);
        ops.addView(smallBtn("路由", () -> RoutingActivity.open(this, p.id)));
        ops.addView(smallBtn("测速", () -> latency(p)));
        ops.addView(smallBtn("分享", () -> share(p)));
        ops.addView(smallBtn("删除", () -> Ui.confirm(this, "删除配置", "确定删除 " + p.name + "？", () -> {
            Store.I.remove(p);
            refresh();
        })));
        return ops;
    }

    /** 注入节点没有"地址/端口/凭据"这些概念，直接摊开两类请求的真实去向 */
    private View injectSummary(final Node n) {
        com.lcs.tproxy.inject.Ini c = com.lcs.tproxy.inject.Ini.parse(n.ini);
        LinearLayout box = Ui.column(this);
        box.setPadding(0, Ui.dp(this, 8), 0, 0);
        box.addView(row2("HTTP", (c.httpIp.length() > 0 ? c.httpIp : "跟随目标") + ":" + c.httpPort
                + (c.httpOn ? (c.httpDispose && c.httpFirst.length() > 0 ? " · 注入" : " · 直连") : " · 关闭")));
        box.addView(row2("HTTPS", (c.httpsIp.length() > 0 ? c.httpsIp : "跟随目标") + ":" + c.httpsPort
                + (c.httpsOn ? (c.httpsDispose && c.httpsFirst.length() > 0 ? " · 注入" : " · 直连") : " · 关闭")));
        box.addView(row2("DNS", c.dnsUrl.length() > 0 ? c.dnsUrl
                : (c.dnsIp.length() > 0 ? c.dnsIp + ":" + c.dnsPort : "继承全局")));
        box.addView(row2("模式", c.httpFallbackHttps ? "http 未配置时由 https 接管" : "http/https 各自独立"));
        if (n.udpNode != null) {
            box.addView(row2("UDP", n.udpNode.type.toUpperCase() + " " + n.udpNode.addr()
                    + (n.udpViaInject ? " · 经注入" : " · 直连")));
        }
        return box;
    }

    private View row2(String k, String v) {
        LinearLayout r = Ui.row(this);
        r.setPadding(0, Ui.dp(this, 3), 0, Ui.dp(this, 3));
        TextView key = Ui.text(this, k, 11.5f, Ui.MUTED);
        key.setWidth(Ui.dp(this, 54));
        r.addView(key);
        r.addView(Ui.text(this, v, 11.5f, Ui.INK),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return r;
    }

    private View smallBtn(String s, final Runnable r) {
        TextView t = Ui.pill(this, s, 0xFFF1F3F6, Ui.INK);
        t.setTextSize(12f);
        t.setOnClickListener(v -> r.run());
        return t;
    }

    private View labelRow(String label, View field) {
        LinearLayout row = Ui.row(this);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = Ui.dp(this, 8);
        row.setLayoutParams(lp);
        TextView l = Ui.text(this, label, 12f, Ui.MUTED);
        l.setWidth(Ui.dp(this, 52));
        row.addView(l);
        row.addView(field, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private String passwordOf(Node n) {
        if (Node.VLESS.equals(n.type) || Node.VMESS.equals(n.type)) return n.uuid;
        return n.password;
    }

    private void setPassword(Node n, String s) {
        if (Node.VLESS.equals(n.type) || Node.VMESS.equals(n.type)) n.uuid = s;
        else n.password = s;
    }

    /* ------------------------------------------------------------------ actions */

    private void toggle() {
        if (Control.busy()) {
            Ui.toast(this, Control.state.equals("stopping") ? "正在停止，请稍候" : "正在连接，请勿重复点击");
            return;
        }
        if (Engine.I.isRunning()) {
            Control.stop(this);
            refresh();
            return;
        }
        if (Store.I.selected() == null || Store.I.selected().chain.isEmpty()) {
            Ui.toast(this, "先添加一个配置");
            return;
        }
        if ("vpn".equals(Store.I.settings.mode)) {
            Intent prep = VpnService.prepare(this);
            if (prep != null) {
                pendingStart = true;
                startActivityForResult(prep, reqVpn);
                return;
            }
        }
        doStart();
    }

    private void doStart() {
        new Thread(new Runnable() {
            public void run() {
                final String err = Control.start(MainActivity.this);
                runOnUiThread(new Runnable() {
                    public void run() {
                        if (err != null) Ui.info(MainActivity.this, "启动失败", err);
                        refresh();
                    }
                });
            }
        }).start();
        refresh();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == reqVpn) {
            if (res == RESULT_OK && pendingStart) doStart();
            else Ui.toast(this, "未授权 VPN");
            pendingStart = false;
        } else if (req == reqShareFile && res == RESULT_OK && data != null
                && data.getData() != null && pendingShareLink != null) {
            try {
                java.io.OutputStream out = getContentResolver().openOutputStream(data.getData());
                out.write(pendingShareLink.getBytes("UTF-8"));
                out.flush();
                out.close();
                Ui.toast(this, "配置已导出");
            } catch (Exception e) {
                Ui.toast(this, "导出失败");
            }
            pendingShareLink = null;
        }
    }

    private void createProfile() {
        /* 不再直接 Store.add：先开编辑器，点了保存才进列表（草稿语义）。 */
        EditActivity.openNew(this);
    }

    private void importDialog() {
        Ui.promptDialog(this, "粘贴分享链接或完整配置", "", text -> {
            List<Profile> got = Links.parse(text);
            if (got.isEmpty()) {
                Ui.toast(this, "没识别到可用的配置");
                return;
            }
            for (Profile p : got) Store.I.profiles.add(0, p);
            Store.I.selectedId = got.get(0).id;
            Store.I.save();
            expanded.clear();
            refresh();
            if (Control.running()) {
                Control.disconnectSoon(this);
                Ui.toast(this, "已导入 " + got.size() + " 个配置，已断开连接");
            } else {
                Ui.toast(this, "已导入 " + got.size() + " 个配置");
            }
        });
    }

    /** 测速：HTTP 和 HTTPS 分开测，用户才能看出哪一路有网。
     *  引擎在跑就走本地代理端口（http 直发、https 走 CONNECT），没跑就只测节点可达性。 */
    private void latency(final Profile p) {
        final Node e = p.exit();
        if (e == null) {
            Ui.toast(this, "没有出口节点");
            return;
        }
        final boolean running = Engine.I.isRunning();
        if (!running && Node.INJECT.equals(e.type)) {
            Ui.toast(this, "注入节点没有独立地址，需启动引擎后测试");
            return;
        }
        Ui.toast(this, running ? "分别测 HTTP / HTTPS…" : "引擎未运行，只测节点可达性…");
        new Thread(new Runnable() {
            public void run() {
                String msg;
                boolean good;
                if (running) {
                    int h = probeMs(Engine.I.httpPort, "http://www.baidu.com/");
                    int hs = probeMs(Engine.I.httpPort, "https://www.baidu.com/");
                    good = h > 0 || hs > 0;
                    msg = "HTTP " + (h > 0 ? h + "ms" : "不通")
                            + " · HTTPS " + (hs > 0 ? hs + "ms" : "不通");
                    if (!good && Engine.I.injectStatus() != null) msg += "\n" + Engine.I.injectStatus();
                } else {
                    long t0 = System.currentTimeMillis();
                    good = tcpProbe(e.host, e.port);
                    msg = (good ? "节点可达 " : "节点不可达 ") + (System.currentTimeMillis() - t0)
                            + "ms（未验证隧道）";
                }
                final String d = msg;
                final boolean ok = good;
                runOnUiThread(() -> Ui.toast(MainActivity.this, (ok ? "" : "都不通：\n") + d));
            }
        }).start();
    }

    private static boolean tcpProbe(String host, int port) {
        Socket s = new Socket();
        try {
            s.connect(new java.net.InetSocketAddress(host, port), 2500);
            return true;
        } catch (Exception ignored) {
            return false;
        } finally {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    /** 通过本地代理端口请求一个 URL，返回耗时毫秒；-1 = 失败。
     *  http 用绝对 URI 直发，https 由 HttpURLConnection 自己发 CONNECT 再握手，两路都能测。 */
    private static int probeMs(int proxyPort, String url) {
        long t0 = System.currentTimeMillis();
        java.net.HttpURLConnection c = null;
        try {
            java.net.Proxy px = new java.net.Proxy(java.net.Proxy.Type.HTTP,
                    new java.net.InetSocketAddress("127.0.0.1", proxyPort));
            c = (java.net.HttpURLConnection) new java.net.URL(url).openConnection(px);
            c.setConnectTimeout(6000);
            c.setReadTimeout(9000);
            c.setInstanceFollowRedirects(false);
            c.setRequestProperty("User-Agent", "TinyProxyX");
            int code = c.getResponseCode();
            return code > 0 ? (int) (System.currentTimeMillis() - t0) : -1;
        } catch (Exception ignored) {
            return -1;
        } finally {
            if (c != null) {
                try {
                    c.disconnect();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static final int reqShareFile = 2002;
    private String pendingShareLink;

    private void share(Profile p) {
        if (p.chain.isEmpty()) return;
        if (p.chain.size() != 1 || Node.INJECT.equals(p.chain.get(0).type)) {
            Ui.info(this, "暂不支持导出",
                    "链式配置和注入配置不能可靠还原成单条分享链接，已停止导出，避免导入后变成多个独立配置。");
            return;
        }
        final String link = Links.toLink(p.chain.get(0));
        if (link.length() == 0) {
            Ui.toast(this, "该协议暂不支持分享链接");
            return;
        }
        Ui.choose(this, "导出配置", new String[]{"复制到剪贴板", "导出为文件", "分享文本"}, i -> {
            if (i == 0) {
                android.content.ClipboardManager cm =
                        (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                cm.setPrimaryClip(android.content.ClipData.newPlainText("proxy", link));
                Ui.toast(this, "已复制到剪贴板");
            } else if (i == 1) {
                pendingShareLink = link;
                Intent it = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                it.addCategory(Intent.CATEGORY_OPENABLE);
                it.setType("text/plain");
                it.putExtra(Intent.EXTRA_TITLE,
                        "TinyProxyX-" + p.chain.get(0).title().replaceAll("[\\\\/:*?\"<>|]", "_") + ".txt");
                try {
                    startActivityForResult(it, reqShareFile);
                } catch (Exception e) {
                    Ui.toast(this, "没有文件选择器");
                }
            } else {
                Intent it = new Intent(Intent.ACTION_SEND);
                it.setType("text/plain");
                it.putExtra(Intent.EXTRA_TEXT, link);
                startActivity(Intent.createChooser(it, "分享配置"));
            }
        });
    }
}

