package com.lcs.tproxy.ui;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;

import com.lcs.tproxy.core.Bin;
import com.lcs.tproxy.core.CoreInstall;
import com.lcs.tproxy.core.Control;
import com.lcs.tproxy.core.Engine;
import com.lcs.tproxy.core.Updater;
import com.lcs.tproxy.model.Store;

import java.io.InputStream;

public class SettingsActivity extends Activity {

    private LinearLayout content;
    private int reqFile = 2001;
    private String importTarget = Bin.XRAY;
    private String importGeoName;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Ui.lightStatus(this);
        setContentView(build());
        render();
    }

    @Override
    protected void onResume() {
        super.onResume();
        /* DnsActivity 保存后回到这里，必须重绘卡片，否则还显示旧解析器。 */
        if (content != null) render();
    }

    private View build() {
        LinearLayout root = Ui.column(this);
        root.setBackgroundColor(Ui.BG);
        LinearLayout bar = Ui.row(this);
        bar.setBackgroundColor(Ui.WHITE);
        int p = Ui.dp(this, 16);
        bar.setPadding(p, Ui.dp(this, 14), p, Ui.dp(this, 14));
        TextView back = Ui.text(this, "‹ 返回", 15f, Ui.ACCENT);
        back.setOnClickListener(v -> finish());
        bar.addView(back);
        TextView title = Ui.text(this, "设置", 17f, Ui.INK);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setGravity(android.view.Gravity.CENTER);
        bar.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView done = Ui.text(this, "完成", 15f, Ui.ACCENT);
        done.setOnClickListener(v -> finish());
        bar.addView(done);
        root.addView(bar);
        content = Ui.column(this);
        root.addView(Ui.page(this, content), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    /* ------------------------------------------------------------------ render */

    private void render() {
        content.removeAllViews();
        final Store.Settings s = Store.I.settings;

        /* ---- run mode */
        LinearLayout mode = Ui.card(this);
        mode.addView(Ui.label(this, "运行方式"));
        mode.addView(Ui.text(this, "VPN：不需要 root，用系统 VPN 通道接管全部流量（默认）\n"
                + "热点：用 iptables 透明代理，同时接管本机与热点 / USB / 以太网的转发", 11.5f, Ui.MUTED));
        LinearLayout modeRow = Ui.row(this);
        modeRow.setPadding(0, Ui.dp(this, 8), 0, 0);
        final String[] modes = {"vpn", "root"};
        final String[] names = {"VPN", "热点"};
        for (int i = 0; i < modes.length; i++) {
            final String m = modes[i];
            boolean on = m.equals(s.mode);
            TextView chip = Ui.pill(this, names[i], on ? Ui.ACCENT : 0xFFF1F3F6, on ? Ui.WHITE : Ui.INK);
            chip.setTextSize(12.5f);
            chip.setOnClickListener(v -> {
                boolean changed = !m.equals(s.mode);
                s.mode = m;
                Store.I.save();
                render();
                /* 模式改了只断开，不自动重连（之前 stop→start 会在切模式时闪退） */
                if (changed && com.lcs.tproxy.core.Control.running()) {
                    com.lcs.tproxy.core.Control.disconnectSoon(this);
                    Ui.toast(this, "已断开当前连接，回主页按新模重连");
                }
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            lp.rightMargin = Ui.dp(this, 8);
            modeRow.addView(chip, lp);
        }
        mode.addView(modeRow);
        content.addView(mode, block());

        /* ---- cores, one row per core, each with its own check / link / import */
        LinearLayout core = Ui.card(this);
        core.addView(Ui.label(this, "内核"));
        LinearLayout hev = Ui.column(this);
        hev.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 8));
        LinearLayout hevTop = Ui.row(this);
        TextView hevName = Ui.text(this, "hev-socks5-tunnel", 14f, Ui.INK);
        hevName.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        hevTop.addView(hevName, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        hevTop.addView(Ui.pill(this, "内置 2.19.3", 0xFFEAF7EF, Ui.OK));
        hev.addView(hevTop);
        hev.addView(Ui.text(this, "tun → socks 转发层，进程内 JNI 调用，随 APK 更新；"
                + "不再需要单独的 tun2socks 可执行文件。", 11.5f, Ui.MUTED));
        core.addView(hev);
        core.addView(Ui.label(this, "可更新核心"));
        core.addView(Ui.text(this, "「更新」里可选择检查在线版本、设置下载链接、从文件导入或还原内置。",
                11f, Ui.MUTED));
        for (int i = 0; i < CoreInstall.NAMES.length; i++) {
            final String name = CoreInstall.NAMES[i];
            LinearLayout row = Ui.row(this);
            row.setPadding(0, Ui.dp(this, 9), 0, Ui.dp(this, 9));
            LinearLayout info = Ui.column(this);
            TextView t = Ui.text(this, CoreInstall.LABELS[i] + "  ·  " + name, 14f, Ui.INK);
            t.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            info.addView(t);
            info.addView(Ui.text(this, Bin.version(this, name), 11.5f, Ui.MUTED));
            row.addView(info, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            TextView upd = Ui.pill(this, "更新", Ui.NEUTRAL, Ui.INK);
            upd.setTextSize(12f);
            upd.setOnClickListener(v -> coreMenu(name));
            LinearLayout.LayoutParams ulp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            ulp.setMargins(Ui.dp(this, 8), 0, 0, 0);
            row.addView(upd, ulp);
            core.addView(row);
        }
        content.addView(core, block());

        /* ---- geo data: two independent databases */
        LinearLayout geo = Ui.card(this);
        geo.addView(Ui.label(this, "路由数据库"));
        geo.addView(geoRow("geoip.dat"));
        geo.addView(geoRow("geosite.dat"));
        TextView gupd = Ui.pill(this, "更新规则库（同源 zip）", Ui.NEUTRAL, Ui.INK);
        gupd.setOnClickListener(v -> Ui.confirm(this, "更新规则库",
                "从当前 Xray 发布 zip 同时替换 geoip.dat 与 geosite.dat；"
                        + "两份文件必须同源，失败不会改动现有文件。", () -> {
                    Control.disconnectSoon(this);
                    Ui.toast(this, "开始更新规则库");
                    Updater.updateGeoBoth(this, geoCb("geoip.dat"));
                }));
        geo.addView(gupd);
        geo.addView(Ui.text(this, "更新会同时替换两份文件，避免 Xray/v2fly 混用；"
                + "单独导入/还原仍按文件操作。", 11f, Ui.MUTED));
        content.addView(geo, block());

        /* ---- global dns */
        LinearLayout dnsc = Ui.card(this);
        dnsc.addView(Ui.label(this, "DNS"));
        dnsc.addView(rows("全局 DNS",
                s.dnsEnabled
                        ? (s.dnsRemote.length() > 0 ? s.dnsRemote : "同国内")
                        + " / " + (s.dnsDomestic.length() > 0 ? s.dnsDomestic : "223.5.5.5")
                        + " · 53 策略在路由页"
                        : "未启用（上游跟随系统）"));
        dnsc.addView(rows("Bootstrap", s.bootEnabled
                ? (s.bootIp.length() > 0 ? s.bootIp : "还没填 IP")
                + " · " + ("secure".equals(s.bootMode) ? "加密" : "明文")
                + " · 只在首次解析用"
                : "未启用"));
        TextView dnsBtn = Ui.pill(this, "设置 DNS", 0xFFF1F3F6, Ui.INK);
        dnsBtn.setOnClickListener(v -> DnsActivity.open(this));
        dnsc.addView(dnsBtn);
        content.addView(dnsc, block());

        /* ---- ports */
        LinearLayout ports = Ui.card(this);
        ports.addView(Ui.label(this, "本地端口"));
        ports.addView(portRow("SOCKS5", s.socksPort, v -> {
            s.socksPort = v;
            Store.I.save();
            Control.disconnectSoon(this);
        }));
        ports.addView(portRow("HTTP", s.httpPort, v -> {
            s.httpPort = v;
            Store.I.save();
            Control.disconnectSoon(this);
        }));
        ports.addView(portRow("TPROXY（root）", s.tproxyPort, v -> {
            s.tproxyPort = v;
            Store.I.save();
            Control.disconnectSoon(this);
        }));
        ports.addView(portRow("REDIRECT（root）", s.redirectPort, v -> {
            s.redirectPort = v;
            Store.I.save();
            Control.disconnectSoon(this);
        }));
        ports.addView(Ui.text(this, "改了端口要重新连接才生效。注入配置里的 listen_port 会被注入节点自己占用。",
                11f, Ui.MUTED));
        content.addView(ports, block());

        /* ---- behaviour */
        LinearLayout behavior = Ui.card(this);
        behavior.addView(Ui.label(this, "行为"));
        behavior.addView(toggle("允许局域网连接（监听 0.0.0.0）", s.allowLan, v -> {
            s.allowLan = v;
            Store.I.save();
            Control.disconnectSoon(this);
        }));
        behavior.addView(toggle("私有地址 / 局域网直连", s.bypassPrivate, v -> {
            s.bypassPrivate = v;
            Store.I.save();
            Control.disconnectSoon(this);
        }));
        behavior.addView(toggle("优先使用已下载内核", s.preferUpdatedCore, v -> {
            s.preferUpdatedCore = v;
            Store.I.save();
            Control.disconnectSoon(this);
        }));
        behavior.addView(toggle("全局多路复用（mux）", Store.I.selected() != null && Store.I.selected().mux, v -> {
            if (Store.I.selected() != null) {
                Store.I.selected().mux = v;
                Store.I.save();
                Control.disconnectSoon(this);
            }
        }));
        behavior.addView(toggle("流量嗅探（域名还原）", Store.I.selected() == null || Store.I.selected().sniff, v -> {
            if (Store.I.selected() != null) {
                Store.I.selected().sniff = v;
                Store.I.save();
                Control.disconnectSoon(this);
            }
        }));
        content.addView(behavior, block());

        /* ---- subscription (原版 v2订阅) */
        LinearLayout sub = Ui.card(this);
        sub.addView(Ui.label(this, "订阅"));
        sub.addView(Ui.text(this, "每行一个订阅地址，更新时拉取并追加配置（支持分享链接 / 完整配置 / 注入 ini）。",
                11f, Ui.MUTED));
        final EditText subField = Ui.area(this, "https://...", s.subUrls, 3);
        subField.setSingleLine(false);
        sub.addView(subField, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 76),
                0, Ui.dp(this, 6), 0, Ui.dp(this, 6)));
        LinearLayout subOps = Ui.row(this);
        TextView subSave = Ui.pill(this, "保存地址", 0xFFF1F3F6, Ui.INK);
        TextView subGo = Ui.pill(this, "立即更新", Ui.ACCENT, Ui.WHITE);
        subSave.setOnClickListener(v -> {
            s.subUrls = subField.getText().toString().trim();
            Store.I.save();
            Ui.toast(this, "已保存");
        });
        subGo.setOnClickListener(v -> {
            s.subUrls = subField.getText().toString().trim();
            Store.I.save();
            updateSubs();
        });
        subOps.addView(subSave);
        subOps.addView(gap(this, 8));
        subOps.addView(subGo);
        sub.addView(subOps);
        content.addView(sub, block());

        /* ---- battery */
        LinearLayout batt = Ui.card(this);
        batt.addView(Ui.label(this, "后台存活"));
        batt.addView(Ui.text(this, "把本应用加入电池优化白名单，避免连接被系统回收。", 11f, Ui.MUTED));
        TextView bo = Ui.pill(this, "请求忽略电池优化", 0xFFF1F3F6, Ui.INK);
        bo.setOnClickListener(v -> {
            try {
                Intent i = new Intent(
                        android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                i.setData(Uri.parse("package:" + getPackageName()));
                startActivity(i);
            } catch (Exception e) {
                Ui.toast(this, "系统不支持该入口");
            }
        });
        batt.addView(bo);
        content.addView(batt, block());

        /* ---- per app */
        LinearLayout apps = Ui.card(this);
        apps.addView(Ui.label(this, "分应用代理"));
        apps.addView(rows("仅代理 / 排除指定应用",
                Store.I.selected() != null && Store.I.selected().perAppEnabled
                        ? (Store.I.selected().perAppAllowMode ? "白名单 " : "黑名单 ")
                        + Store.I.selected().apps.size() + " 个应用" : "未启用"));
        TextView pick = Ui.pill(this, "选择应用", 0xFFF1F3F6, Ui.INK);
        pick.setOnClickListener(v -> startActivity(new Intent(this, AppPickActivity.class)));
        apps.addView(pick);
        content.addView(apps, block());

        /* ---- about */
        LinearLayout about = Ui.card(this);
        about.addView(Ui.label(this, "关于"));
        about.addView(rows("版本", appVersion()));
        about.addView(rows("当前内核路径", corePath()));
        TextView lg = Ui.pill(this, "查看日志", 0xFFF1F3F6, Ui.INK);
        lg.setOnClickListener(v -> startActivity(new Intent(this, LogActivity.class)));
        about.addView(lg);
        content.addView(about, block());
    }

    private View gap(Activity a, int dp) {
        View v = new View(a);
        v.setLayoutParams(new LinearLayout.LayoutParams(Ui.dp(a, dp), 1));
        return v;
    }

    /** 直接从 manifest 读，别再写死 */
    private String appVersion() {
        try {
            android.content.pm.PackageInfo pi = getPackageManager()
                    .getPackageInfo(getPackageName(), 0);
            return pi.versionName + " (" + pi.versionCode + ")";
        } catch (Exception e) {
            return "?";
        }
    }

    private String corePath() {
        boolean root = "root".equals(Store.I.settings.mode);
        java.io.File f = Bin.resolve(this, Bin.XRAY, root);
        if (f == null) return "未找到";
        return f.getAbsolutePath().replace(getPackageName(), "…");
    }

    private String geoSize(String name) {
        java.io.File f = new java.io.File(Engine.I.assetDir(this), name);
        return f.exists() ? (f.length() >> 20) + "MB" : "缺失";
    }

    private View geoRow(final String name) {
        LinearLayout row = Ui.row(this);
        row.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 8));
        LinearLayout info = Ui.column(this);
        info.addView(Ui.text(this, name, 14f, Ui.INK));
        info.addView(Ui.text(this, geoSize(name), 11.5f, Ui.MUTED));
        row.addView(info, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView imp = Ui.pill(this, "导入", Ui.NEUTRAL, Ui.INK);
        TextView res = Ui.pill(this, "还原", Ui.NEUTRAL, Ui.INK);
        imp.setTextSize(12f);
        res.setTextSize(12f);
        imp.setOnClickListener(v -> {
            importGeoName = name;
            pickFile();
        });
        res.setOnClickListener(v -> Ui.confirm(this, "还原 " + name,
                "恢复 APK 内置版本？", () -> {
                    Control.disconnectSoon(this);
                    Updater.restoreGeo(this, name, geoCb(name));
                }));
        LinearLayout.LayoutParams lp1 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp1.setMargins(Ui.dp(this, 6), 0, 0, 0);
        LinearLayout.LayoutParams lp2 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp2.setMargins(Ui.dp(this, 6), 0, 0, 0);
        row.addView(imp, lp1);
        row.addView(res, lp2);
        return row;
    }

    private void coreMenu(final String core) {
        Ui.choose(this, CoreInstall.label(core), new String[]{
                "检查并更新", "设置下载链接", "从文件导入", "还原内置"}, i -> {
            if (i == 0) {
                checkCore(core);
            } else if (i == 1) {
                Ui.inputDialog(this,
                        core + " 下载链接（zip 或裸二进制，留空恢复默认）",
                        CoreInstall.customUrl(core), val -> {
                            CoreInstall.setCustomUrl(core, val);
                            Control.disconnectSoon(this);
                            render();
                        });
            } else if (i == 2) {
                importTarget = core;
                importGeoName = null;
                pickFile();
            } else {
                Ui.confirm(this, "还原 " + core,
                        "删除已下载/导入的核心，恢复 APK 内置版本？", () -> {
                            boolean ok = Bin.restore(this, core);
                            Control.disconnectSoon(this);
                            Ui.toast(this, ok ? "已还原内置核心" : "还原失败");
                            render();
                        });
            }
        });
    }

    private void geoMenu(final String name) {
        Ui.choose(this, name, new String[]{"在线更新", "从文件导入", "还原内置"}, i -> {
            if (i == 0) {
                Control.disconnectSoon(this);
                Ui.toast(this, "开始更新 " + name);
                Updater.updateGeoOne(this, name, geoCb(name));
            } else if (i == 1) {
                importGeoName = name;
                pickFile();
            } else {
                Ui.confirm(this, "还原 " + name, "恢复 APK 内置版本？", () -> {
                    Control.disconnectSoon(this);
                    Updater.restoreGeo(this, name, geoCb(name));
                });
            }
        });
    }

    private Updater.Cb geoCb(final String name) {
        return new Updater.Cb() {
            public void onLog(String line) {
            }

            public void onDone(final boolean ok, final String msg) {
                runOnUiThread(() -> {
                    Ui.info(SettingsActivity.this, ok ? "完成" : "失败", msg);
                    render();
                });
            }
        };
    }

    private View rows(String title, String sub) {
        LinearLayout l = Ui.column(this);
        l.setPadding(0, Ui.dp(this, 7), 0, Ui.dp(this, 7));
        l.addView(Ui.text(this, title, 14f, Ui.INK));
        if (sub != null && sub.length() > 0) l.addView(Ui.text(this, sub, 11.5f, Ui.MUTED));
        return l;
    }

    private LinearLayout.LayoutParams block() {
        return Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                0, 0, 0, Ui.dp(this, 10));
    }

    private View toggle(String label, boolean value, final BoolSink sink) {
        LinearLayout row = Ui.row(this);
        row.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 4));
        row.addView(Ui.text(this, label, 13.5f, Ui.INK),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        final Switch sw = new Switch(this);
        sw.setChecked(value);
        sw.setOnCheckedChangeListener((btn, checked) -> sink.run(checked));
        row.addView(sw);
        return row;
    }

    private View portRow(String label, int value, final IntSink sink) {
        LinearLayout row = Ui.row(this);
        row.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 4));
        row.addView(Ui.text(this, label, 13.5f, Ui.INK),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView v = Ui.text(this, String.valueOf(value), 13.5f, Ui.ACCENT);
        v.setOnClickListener(x -> Ui.inputDialog(this, label, String.valueOf(value), val -> {
            try {
                int port = Integer.parseInt(val.trim());
                if (port < 1 || port > 65535) throw new NumberFormatException("range");
                Store.Settings current = Store.I.settings;
                int[] others = {current.socksPort, current.httpPort, current.tproxyPort, current.redirectPort};
                int duplicates = 0;
                for (int p : others) if (p == port) duplicates++;
                if (duplicates > 1) {
                    Ui.toast(this, "四个本地端口不能重复");
                    return;
                }
                sink.run(port);
                render();
            } catch (Exception e) {
                Ui.toast(this, "端口无效");
            }
        }));
        row.addView(v);
        return row;
    }

    private interface BoolSink {
        void run(boolean v);
    }

    private interface IntSink {
        void run(int v);
    }

    /* ------------------------------------------------------------------ cores */

    private void checkCore(final String core) {
        boolean rootMode = "root".equals(Store.I.settings.mode);
        if (Bin.XRAY.equals(core) && Bin.hasUpdated(this, core) && !rootMode
                && !Bin.probe(Bin.updated(this, core), core)) {
            Ui.info(this, "已下载，但当前模式不能执行",
                    "普通模式不能从 /data/user/0 执行下载的核心。\n"
                            + "切到 ROOT 模式后会自动复制到 /data/local/tmp 运行，"
                            + "或先“还原内置”。");
            return;
        }
        String url = CoreInstall.customUrl(core);
        if (url.length() > 0 && !Bin.XRAY.equals(core)) {
            Ui.confirm(this, "下载 " + core, "使用链接：\n" + url, () -> start(core, url));
            return;
        }
        if (!Bin.XRAY.equals(core)) {
            Ui.info(this, CoreInstall.label(core),
                    "该核心没有官方 Android 发布源。\n用“更新 → 设置下载链接”填一个 zip / 二进制直链，"
                            + "或用“从文件导入”安装。");
            return;
        }
        Ui.toast(this, "查询最新版本…");
        new Thread(() -> {
            final String[] r = CoreInstall.checkUpstream(Bin.XRAY);
            runOnUiThread(() -> {
                String tag = r[0];
                String dl = r[1];
                if (dl.length() == 0) {
                    Ui.info(this, "查询失败", "拿不到 Xray 发布信息，可以用“更新 → 设置下载链接”指定地址。");
                    return;
                }
                final String dlUrl = dl;
                String current = Bin.version(this, Bin.XRAY);
                String a = current.toLowerCase().replace("v", "");
                String b = tag.toLowerCase().replace("v", "");
                if (b.length() > 0 && a.contains(b)) {
                    Ui.info(this, "已是最新", "当前：" + current);
                    return;
                }
                Ui.confirm(this, "Xray " + tag, "当前：" + current
                        + "\n\n是否下载并安装这个版本？", () -> start(Bin.XRAY, dlUrl));
            });
        }).start();
    }

    private void start(String core, String url) {
        Ui.toast(this, "开始下载 " + core);
        CoreInstall.download(this, core, url, new CoreInstall.Cb() {
            public void onDone(final boolean ok, final String msg) {
                runOnUiThread(() -> {
                    Ui.info(SettingsActivity.this, ok ? "完成" : "失败", msg);
                    render();
                });
            }
        });
    }

    private void updateSubs() {
        final String urls = Store.I.settings.subUrls;
        if (urls.trim().length() == 0) {
            Ui.toast(this, "先填订阅地址");
            return;
        }
        Ui.toast(this, "开始更新订阅…");
        new Thread(() -> {
            int added = 0;
            int failed = 0;
            for (String u : urls.split("[\\r\\n]+")) {
                String url = u.trim();
                if (url.length() < 8) continue;
                String body = Updater.fetchText(url);
                if (body.length() == 0) {
                    failed++;
                    continue;
                }
                java.util.List<com.lcs.tproxy.model.Profile> got =
                        com.lcs.tproxy.link.Links.parse(body);
                if (got.isEmpty()) {
                    /* subscriptions are often base64 of a link list */
                    try {
                        String dec = new String(android.util.Base64.decode(
                                body.trim(), android.util.Base64.DEFAULT), "UTF-8");
                        got = com.lcs.tproxy.link.Links.parse(dec);
                    } catch (Exception ignored) {
                    }
                }
                for (com.lcs.tproxy.model.Profile p2 : got) {
                    Store.I.profiles.add(p2);
                    added++;
                }
                if (got.isEmpty()) failed++;
            }
            /* 订阅可能替换了某个被 UDP 转换引用的节点：导入完成后立刻对一次账。 */
            com.lcs.tproxy.model.NodeSync.reconcile();
            final int a = added;
            final int f = failed;
            Store.I.save();
            runOnUiThread(() -> {
                Ui.info(SettingsActivity.this, "订阅更新完成",
                        "新增 " + a + " 个配置" + (f > 0 ? "，" + f + " 个地址失败" : ""));
                render();
            });
        }).start();
    }

    private void pickFile() {
        Intent it = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        it.addCategory(Intent.CATEGORY_OPENABLE);
        it.setType("*/*");
        try {
            startActivityForResult(it, reqFile);
        } catch (Exception e) {
            Ui.toast(this, "没有文件选择器");
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == reqFile && res == RESULT_OK && data != null && data.getData() != null) {
            Uri u = data.getData();
            try {
                InputStream in = getContentResolver().openInputStream(u);
                if (importGeoName != null) {
                    Updater.importGeo(this, importGeoName, in, geoCb(importGeoName));
                    importGeoName = null;
                } else {
                    CoreInstall.importFile(this, importTarget, in, new CoreInstall.Cb() {
                        public void onDone(final boolean ok, final String msg) {
                            runOnUiThread(() -> {
                                Ui.info(SettingsActivity.this, ok ? "导入完成" : "导入失败", msg);
                                render();
                            });
                        }
                    });
                }
            } catch (Exception e) {
                Ui.toast(this, "读取失败");
            }
        }
    }
}
