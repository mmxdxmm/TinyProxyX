package com.lcs.tproxy.ui;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;

import com.lcs.tproxy.core.Control;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.root.Root;

import java.util.ArrayList;
import java.util.List;

/**
 * 热点 / 网卡代理设置。
 *
 * <p>这一页是草稿模型：页面上的开关、网卡选择只改本地字段，点右上角「完成」才写进 Store，
 * 直接返回等于放弃（脏了先问一句）。之前是每点一下开关就 {@code Store.I.save()}，
 * 没点完成也已经生效 —— 这就是「返回即保存」在热点模式里的那一处。</p>
 */
public class RootActivity extends Activity {

    /* ---------------------------------------------------------------- 草稿 */
    private boolean dLocal = true;
    private boolean dHotspot = true;
    private boolean dUdp = true;
    private final List<String> dProxy = new ArrayList<String>();
    private final List<String> dBypass = new ArrayList<String>();
    private boolean dirty;

    private LinearLayout box;
    private TextView stateView;
    private TextView modeView;
    private TextView hotspotView;
    private TextView hintView;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Ui.lightStatus(this);
        loadDraft();
        setContentView(build());
        render();
    }

    @Override
    protected void onResume() {
        super.onResume();
        /* 只重画，不重读 Store：草稿还在编辑中 */
        render();
    }

    /* ------------------------------------------------------------ 草稿模型 */

    private void loadDraft() {
        Store.Settings s = Store.I.settings;
        dLocal = s.rootProxyLocal;
        dHotspot = s.rootHotspot;
        dUdp = s.rootUdp;
        dProxy.clear();
        dProxy.addAll(s.proxyIfs);
        dBypass.clear();
        dBypass.addAll(s.bypassIfs);
        dirty = false;
    }

    /** 草稿 + 未改动的其余设置，用来画脚本 / 手工应用规则 */
    private Store.Settings snapshot() {
        Store.Settings s = Store.Settings.fromJson(Store.I.settings.toJson());
        s.rootProxyLocal = dLocal;
        s.rootHotspot = dHotspot;
        s.rootUdp = dUdp;
        s.proxyIfs = new ArrayList<String>(dProxy);
        s.bypassIfs = new ArrayList<String>(dBypass);
        return s;
    }

    /** 点「完成」：草稿一次性落盘 */
    private void commit() {
        Store.Settings s = Store.I.settings;
        s.rootProxyLocal = dLocal;
        s.rootHotspot = dHotspot;
        s.rootUdp = dUdp;
        s.proxyIfs.clear();
        s.proxyIfs.addAll(dProxy);
        s.bypassIfs.clear();
        s.bypassIfs.addAll(dBypass);
        Store.I.save();
        dirty = false;
        boolean was = Control.running();
        if (was) Control.disconnect(this);
        Ui.toast(this, was ? "已保存，已断开连接（新设置下次连接时生效）" : "热点设置已保存");
        finish();
    }

    /** 返回 = 放弃：脏了先问一句 */
    private void leave() {
        if (!dirty) {
            finish();
            return;
        }
        Ui.confirm(this, "放弃这次修改？", "热点设置里改的东西还没保存，返回就丢掉了。", new Runnable() {
            public void run() {
                finish();
            }
        });
    }

    @Override
    public void onBackPressed() {
        leave();
    }

    private void touch() {
        dirty = true;
    }

    /* ------------------------------------------------------------------ UI */

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
        TextView title = Ui.text(this, "热点 / 网卡代理", 17f, Ui.INK);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setGravity(android.view.Gravity.CENTER);
        bar.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView done = Ui.text(this, "完成", 15f, Ui.ACCENT);
        done.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        done.setOnClickListener(v -> commit());
        bar.addView(done);
        root.addView(bar);

        LinearLayout content = Ui.column(this);
        LinearLayout status = Ui.card(this);
        status.addView(Ui.label(this, "ROOT 权限"));
        stateView = Ui.text(this, "", 14f, Ui.INK);
        status.addView(stateView);
        TextView check = Ui.pill(this, "重新检测", Ui.NEUTRAL, Ui.INK);
        check.setOnClickListener(v -> render());
        status.addView(check);
        hintView = Ui.text(this, "改了还没保存：点右上角「完成」才生效，返回则丢弃。", 11.5f, Ui.WARN);
        hintView.setVisibility(View.GONE);
        status.addView(hintView);
        content.addView(status, block());

        LinearLayout mode = Ui.card(this);
        mode.addView(Ui.label(this, "接管范围"));
        modeView = Ui.text(this, "", 13.5f, Ui.INK);
        mode.addView(modeView);
        mode.addView(Ui.text(this, "IPv4：本机与转发的 TCP 走 REDIRECT；UDP 按策略处理。\n"
                + "IPv6：走 mangle TPROXY。\n"
                + "UDP、QUIC 443、DNS 的「禁用/代理/直连」在「路由」页分别选择；"
                + "默认 UDP/QUIC 禁用、DNS 代理，不会自动直连。",
                11.5f, Ui.MUTED));
        mode.addView(switchRow("接管本地应用流量", dLocal, v -> dLocal = v));
        mode.addView(switchRow("代理转发流量（热点 / USB / 以太网）", dHotspot, v -> dHotspot = v));
        TextView policyBtn = Ui.pill(this, "UDP / QUIC 443 / DNS 策略", Ui.NEUTRAL, Ui.INK);
        policyBtn.setOnClickListener(v -> {
            Profile sel = Store.I.selected();
            if (sel != null) RoutingActivity.open(this, sel.id);
        });
        mode.addView(policyBtn);
        content.addView(mode, block());

        LinearLayout ifs = Ui.card(this);
        ifs.addView(Ui.label(this, "网卡"));
        hotspotView = Ui.text(this, "", 12f, Ui.ACCENT);
        ifs.addView(hotspotView);
        ifs.addView(Ui.text(this, "蓝 = 走隧道，灰 = 直连。启动时会重新扫描一次热点网卡并自动并入代理名单"
                + "（ap0 / softap0 / swlan0 / br0 / rndis0 之类只有开热点才出现）。",
                11.5f, Ui.MUTED));
        FlowLayout quick = new FlowLayout(this, Ui.dp(this, 8), Ui.dp(this, 8));
        quick.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 8));
        TextView all = Ui.pill(this, "全部网卡", Ui.NEUTRAL, Ui.INK);
        TextView auto = Ui.pill(this, "自动识别热点", Ui.NEUTRAL, Ui.INK);
        all.setOnClickListener(v -> {
            dProxy.clear();
            dProxy.add("*");
            dBypass.clear();
            touch();
            render();
        });
        auto.setOnClickListener(v -> {
            dProxy.clear();
            dBypass.clear();
            for (Root.Iface f : Root.interfaces()) if (f.hotspot) dProxy.add(f.name);
            if (dProxy.isEmpty()) dProxy.add("*");
            touch();
            render();
            Ui.toast(this, "已选择 " + dProxy.size() + " 个网卡（还没保存）");
        });
        quick.addView(all);
        quick.addView(auto);
        ifs.addView(quick);

        box = Ui.column(this);
        ifs.addView(box);
        content.addView(ifs, block());

        LinearLayout ops = Ui.card(this);
        ops.addView(Ui.label(this, "执行"));
        ops.addView(Ui.text(this, "规则在连接时按这一页的设置自动生成、断开时自动清理，一般不需要手动干预。"
                + "「应用规则」只在已连接时可用——它会把当前连接断开，让你按新设置重连；"
                + "没连接时手动下发规则只会把流量推给一个不存在的端口。", 11.5f, Ui.MUTED));
        /* 三个 pill 放进 FlowLayout：每个之间都有 8dp 间距，边框不会再贴在一起 */
        FlowLayout row = new FlowLayout(this, Ui.dp(this, 8), Ui.dp(this, 8));
        row.setPadding(0, Ui.dp(this, 10), 0, 0);
        TextView apply = Ui.pill(this, "应用规则", Ui.ACCENT, Ui.WHITE);
        TextView clean = Ui.pill(this, "清理规则", 0xFFFFEFF0, Ui.DANGER);
        TextView preview = Ui.pill(this, "查看脚本", Ui.NEUTRAL, Ui.INK);
        apply.setOnClickListener(v -> {
            if (!Control.running()) {
                Ui.info(this, "不需要单独应用",
                        "规则在连接时按这一页的设置生成。现在没有连接，手动下发只会把流量"
                                + "推给一个不存在的端口，整机断网。");
                return;
            }
            Control.disconnect(this);
            Ui.info(this, "已断开连接",
                    "运行中不能直接改接管规则。已按最新设置断开，回主页点一下按钮重连即可。");
        });
        clean.setOnClickListener(v -> {
            if (Control.running()) {
                Ui.toast(this, "先断开连接，再清理规则");
                return;
            }
            Ui.toast(this, "正在清理并核验");
            new Thread(() -> {
                boolean cleaned = Root.cleanup(this);
                Store.I.settings.rootArmed = !cleaned;
                Store.I.save();
                runOnUiThread(() -> Ui.toast(this, cleaned ? "规则已清理并核验" : "清理未完全成功，已保留下次重试标记"));
            }, "manual-root-clean").start();
        });
        preview.setOnClickListener(v -> {
            Store.Settings s = snapshot();
            Ui.info(this, "脚本预览", Root.script(this, s, Root.effectiveIfs(s),
                    s.redirectPort, s.tproxyPort, android.os.Process.myUid(), v6Mode(), Store.I.selected()));
        });
        row.addView(apply);
        row.addView(clean);
        row.addView(preview);
        ops.addView(row);
        content.addView(ops, block());

        root.addView(Ui.page(this, content), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private String applyNow() {
        Store.Settings s = snapshot();
        List<String> ifs = Root.effectiveIfs(s);
        String script = Root.script(this, s, ifs, s.redirectPort, s.tproxyPort,
                android.os.Process.myUid(), v6Mode());
        String err = Root.apply(this, script, 0);
        /* rootArmed 是运行态标记（下次启动兜底清理用），不是这一页的配置草稿 */
        Store.I.settings.rootArmed = err == null;
        Store.I.save();
        return err;
    }

    private static String v6Mode() {
        Profile p = Store.I.selected();
        return p == null ? Profile.V6_PROXY : p.v6;
    }

    private static String pText(String p) {
        if (Profile.UDP_BLOCK.equals(p) || Profile.DNS_BLOCK.equals(p)) return "禁用";
        if (Profile.UDP_DIRECT.equals(p) || Profile.DNS_DIRECT.equals(p)) return "直连";
        return "代理";
    }

    private static String v6Text() {
        String m = v6Mode();
        if (Profile.V6_BLOCK.equals(m)) return "丢弃";
        if (Profile.V6_DIRECT.equals(m)) return "直连（会漏）";
        return "直送链路";
    }

    private LinearLayout.LayoutParams block() {
        return Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                0, 0, 0, Ui.dp(this, 10));
    }

    private View switchRow(String label, boolean value, final BoolSet set) {
        LinearLayout row = Ui.row(this);
        row.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 4));
        row.addView(Ui.text(this, label, 13f, Ui.INK),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        final Switch sw = new Switch(this);
        sw.setChecked(value);
        sw.setOnCheckedChangeListener((b, v) -> {
            set.set(v);
            touch();
            render();
        });
        row.addView(sw);
        return row;
    }

    private interface BoolSet {
        void set(boolean v);
    }

    private void render() {
        final boolean root = Root.hasRoot();
        stateView.setText(root ? "已授权（su 可用）" : "未授权：热点模式不可用");
        stateView.setTextColor(root ? Ui.OK : Ui.DANGER);
        hintView.setVisibility(dirty ? View.VISIBLE : View.GONE);

        Profile sp = Store.I.selected();
        modeView.setText("当前：" + (dLocal ? "本机已接管" : "本机直连")
                + (dHotspot ? " · 转发已接管" : " · 不接管转发")
                + " · UDP " + pText(sp == null ? Profile.UDP_BLOCK : sp.effectiveUdpPolicy())
                + " · QUIC443 " + pText(sp == null ? Profile.UDP_BLOCK : sp.effectiveQuicPolicy())
                + " · DNS " + pText(sp == null ? Profile.DNS_PROXY : sp.effectiveDnsPolicy())
                + " · IPv6 " + v6Text());

        List<Root.Iface> hot = Root.interfaces();
        StringBuilder hs = new StringBuilder("当前热点网卡：");
        int n = 0;
        for (Root.Iface f : hot) {
            if (!f.hotspot || !f.up) continue;
            hs.append(n++ > 0 ? "、" : "").append(f.name);
        }
        hotspotView.setText(n == 0 ? "当前热点网卡：未检测到（开热点后自动出现）" : hs.toString());

        box.removeAllViews();
        if (hot.isEmpty()) {
            box.addView(Ui.text(this, "读不到网卡", 12f, Ui.MUTED));
            return;
        }
        boolean all = dProxy.isEmpty() || dProxy.contains("*");
        for (final Root.Iface f : hot) {
            boolean proxied = all ? !dBypass.contains(f.name) : dProxy.contains(f.name);
            LinearLayout row = Ui.row(this);
            row.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 6));
            LinearLayout names = Ui.column(this);
            TextView nm = Ui.text(this, f.name + (f.hotspot ? "  · 热点" : ""), 13.5f,
                    f.up ? Ui.INK : Ui.MUTED);
            nm.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            names.addView(nm);
            names.addView(Ui.text(this, (f.addr == null ? "无地址" : f.addr) + (f.up ? " · UP" : " · DOWN"),
                    11f, Ui.MUTED));
            row.addView(names, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            TextView chip = Ui.pill(this, proxied ? "代理" : "直连",
                    proxied ? Ui.ACCENT_SOFT : Ui.NEUTRAL, proxied ? Ui.ACCENT : Ui.MUTED);
            chip.setOnClickListener(v -> {
                boolean allNow = dProxy.isEmpty() || dProxy.contains("*");
                if (allNow) {
                    if (dBypass.contains(f.name)) dBypass.remove(f.name);
                    else dBypass.add(f.name);
                } else {
                    if (dProxy.contains(f.name)) dProxy.remove(f.name);
                    else dProxy.add(f.name);
                }
                touch();
                render();
            });
            row.addView(chip);
            box.addView(row);
        }
    }
}
