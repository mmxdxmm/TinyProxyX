package com.lcs.tproxy.ui;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;

import com.lcs.tproxy.inject.Boot;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.xray.Conf;

import java.util.Map;

/** Global DNS: remote + domestic resolver, 53 hijack, and the first-resolve bootstrap. */
public class DnsActivity extends Activity {

    private LinearLayout content;
    private EditText remoteField;
    private EditText domesticField;
    private EditText bootIpField;
    private EditText bootPortField;
    private EditText bootSniField;
    /* 草稿：开关和输入框都改这份，点「保存」才写回 Store */
    private boolean dnsEnabled;
    private boolean dnsHijack;
    private boolean bootEnabled;
    private boolean bootSecure;
    private boolean dirty;

    public static void open(Activity a) {
        a.startActivity(new Intent(a, DnsActivity.class));
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Ui.lightStatus(this);
        Store.Settings s = Store.I.settings;
        dnsEnabled = s.dnsEnabled;
        dnsHijack = s.dnsHijack;
        bootEnabled = s.bootEnabled;
        bootSecure = Boot.SECURE.equals(s.bootMode);
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
        TextView title = Ui.text(this, "DNS", 17f, Ui.INK);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setGravity(android.view.Gravity.CENTER);
        bar.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView save = Ui.text(this, "保存", 15f, Ui.ACCENT);
        save.setOnClickListener(v -> save());
        bar.addView(save);
        root.addView(bar);

        content = Ui.column(this);
        root.addView(Ui.page(this, content), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private void save() {
        Store.Settings s = Store.I.settings;
        s.dnsRemote = remoteField.getText().toString().trim();
        s.dnsDomestic = domesticField.getText().toString().trim();
        s.dnsEnabled = dnsEnabled;
        s.dnsHijack = dnsHijack;
        s.bootEnabled = bootEnabled;
        s.bootMode = bootSecure ? Boot.SECURE : Boot.PLAIN;
        s.bootIp = bootIpField.getText().toString().trim();
        s.bootPort = port(bootPortField.getText().toString());
        s.bootSni = bootSniField.getText().toString().trim();
        Store.I.save();
        dirty = false;
        com.lcs.tproxy.core.Control.disconnectSoon(this);
        Ui.toast(this, "DNS 已保存，运行配置已断开");
        finish();
    }

    private void render() {
        content.removeAllViews();
        final Store.Settings s = Store.I.settings;

        LinearLayout on = Ui.card(this);
        on.addView(Ui.label(this, "开关"));
        LinearLayout row = Ui.row(this);
        row.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 4));
        row.addView(Ui.text(this, "启用全局 DNS（xray 与 53 劫持共用）", 13.5f, Ui.INK),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        final Switch sw = new Switch(this);
        sw.setChecked(dnsEnabled);
        /* 只改草稿，不重建页面 —— 重建会把已经敲进去的地址冲掉 */
        sw.setOnCheckedChangeListener((b, v) -> {
            dnsEnabled = v;
            dirty = true;
        });
        row.addView(sw);
        on.addView(row);

        on.addView(Ui.text(this, "53 端口是「禁用 / 代理 / 直连」三态，"
                + "在「路由 → DNS / 53」按配置选择；这里只配置上游解析器。",
                11.5f, Ui.MUTED));
        content.addView(on, block());

        LinearLayout r = Ui.card(this);
        r.addView(Ui.label(this, "远程 DNS"));
        r.addView(Ui.text(this, "国外域名 / 兜底。xray 支持三种写法：\n"
                + "  8.8.8.8                            UDP\n"
                + "  tcp://8.8.8.8                      TCP\n"
                + "  https://dns.alidns.com/dns-query   DoH\n"
                + "DoH 写域名就行：启动时先解析成 IP 再写进配置（bootstrap 优先，没开就系统解析）。\n"
                + "证书带那个 IP 就直接用 IP；不带（自建 DoH）就走 dns-pin：连接落到钉死的 IP 上，\n"
                + "SNI 仍是域名 —— 两种情况都走隧道，不会直连。\n"
                + "xray 的 DNS 不支持 tls://（DoT）；要用 DoT 只能写在注入节点的 dns_tcp=tls 里。",
                11.5f, Ui.MUTED));
        remoteField = Ui.field(this, "默认 https://223.5.5.5/dns-query", s.dnsRemote);
        r.addView(remoteField, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 0, Ui.dp(this, 6), 0, Ui.dp(this, 6)));
        r.addView(pillRows(remoteField, new String[][]{
                {"DoH 阿里", "https://dns.alidns.com/dns-query"},
                {"DoH 腾讯", "https://doh.pub/dns-query"},
                {"DoH Cloudflare", "https://cloudflare-dns.com/dns-query"},
                {"TCP Google", "tcp://8.8.8.8"},
                {"UDP Google", "8.8.8.8"},
        }));
        content.addView(r, block());

        LinearLayout d = Ui.card(this);
        d.addView(Ui.label(this, "国内 DNS"));
        d.addView(Ui.text(this, "只用于 geosite:cn / geoip:cn，避免国内域名绕远路。", 11.5f, Ui.MUTED));
        domesticField = Ui.field(this, "默认 https://223.5.5.5/dns-query", s.dnsDomestic);
        d.addView(domesticField, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 0, Ui.dp(this, 6), 0, Ui.dp(this, 6)));
        d.addView(pillRows(domesticField, new String[][]{
                {"阿里 UDP", "223.5.5.5"},
                {"阿里 TCP", "tcp://223.5.5.5"},
                {"阿里 DoH", "https://dns.alidns.com/dns-query"},
                {"腾讯 UDP", "119.29.29.29"},
                {"腾讯 DoH", "https://doh.pub/dns-query"},
                {"114 UDP", "114.114.114.114"},
        }));
        content.addView(d, block());

        content.addView(bootCard(s), block());
        content.addView(pathCard(s), block());

        LinearLayout note = Ui.card(this);
        note.addView(Ui.label(this, "作用范围"));
        note.addView(Ui.text(this, "这套解析器同时给两边用：\n"
                + "1) xray 自己的域名解析（写进配置的 dns 段）；\n"
                + "2) 进隧道后打到 53 端口的查询——被劫持后由它来答。VPN 模式只覆盖本机，"
                + "热点模式覆盖转发进来的设备。\n"
                + "注入节点的解析也继承这里：节点里没写 dns_url / dns_ip 时才用，"
                + "写了就以节点为准。\n\n"
                + "优先级：Bootstrap → 节点 dns_url / dns_ip → 这里的全局 DNS → 系统解析"
                + "（只有 DNS 策略=直连时才会走到系统）。\n"
                + "节点里的 dns_url 是注入器自己的解析器，和这里的全局 DNS 不是一回事。",
                11.5f, Ui.MUTED));
        content.addView(note, block());
    }

    /* ------------------------------------------------------------- bootstrap */

    private LinearLayout bootCard(final Store.Settings s) {
        LinearLayout c = Ui.card(this);
        c.addView(Ui.label(this, "Bootstrap DNS（首次解析）"));

        LinearLayout row = Ui.row(this);
        row.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 4));
        row.addView(Ui.text(this, "启用：连接建立时先问这台 DNS", 13.5f, Ui.INK),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        final Switch sw = new Switch(this);
        sw.setChecked(bootEnabled);
        sw.setOnCheckedChangeListener((b, v) -> {
            bootEnabled = v;
            dirty = true;
        });
        row.addView(sw);
        c.addView(row);

        LinearLayout enc = Ui.row(this);
        enc.setPadding(0, Ui.dp(this, 2), 0, Ui.dp(this, 4));
        enc.addView(Ui.text(this, "加密模式（DoH / DoT）", 13.5f, Ui.INK),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        final Switch es = new Switch(this);
        es.setChecked(bootSecure);
        es.setOnCheckedChangeListener((b, v) -> {
            bootSecure = v;
            dirty = true;
        });
        enc.addView(es);
        c.addView(enc);

        c.addView(Ui.text(this, "启动连接时，节点域名、注入网关域名、解析器域名都先向它解析一次；"
                + "结果只留在内存里，断开连接才清空。期间不再重复查询，也不走系统 DNS。\n"
                + "每次连接都重新解析：域名换了 IP，重连就行，不会写回配置。\n"
                + "明文：UDP 问 53，超时或被截断自动换 TCP。加密：端口 443 = DoH，853 = DoT，"
                + "证书按 SNI 校验，所以加密模式必须填 SNI。",
                11.5f, Ui.MUTED), Ui.lp(this, -1, -2, 0, 6, 0, 0));

        bootIpField = Ui.field(this, "服务器 IP，例如 223.5.5.5", s.bootIp);
        c.addView(bootIpField, Ui.lp(this, -1, -2, 0, 8, 0, 0));

        LinearLayout line = Ui.row(this);
        bootPortField = Ui.field(this, "端口（空 = 53 / 443）", s.bootPort > 0 ? String.valueOf(s.bootPort) : "");
        line.addView(bootPortField, Ui.wp(this, -2, 1, 0, 8, 8, 0));
        bootSniField = Ui.field(this, "SNI（加密时）", s.bootSni);
        line.addView(bootSniField, Ui.wp(this, -2, 1, 0, 8, 0, 0));
        c.addView(line);

        FlowLayout fp = new FlowLayout(this, Ui.dp(this, 6), Ui.dp(this, 6));
        fp.addView(bootPreset("阿里 223.5.5.5", "223.5.5.5", "dns.alidns.com"));
        fp.addView(bootPreset("腾讯 1.12.12.12", "1.12.12.12", "doh.pub"));
        fp.addView(bootPreset("CF 1.1.1.1", "1.1.1.1", "cloudflare-dns.com"));
        fp.addView(bootPreset("Google 8.8.8.8", "8.8.8.8", "dns.google"));
        c.addView(fp, Ui.lp(this, -1, -2, 0, 8, 0, 0));

        TextView test = Ui.pill(this, "测试解析", Ui.ACCENT_SOFT, Ui.ACCENT);
        test.setOnClickListener(v -> Ui.inputDialog(this, "测试解析", "example.com", domain -> probe(domain)));
        c.addView(test, Ui.lp(this, -2, -2, 0, 10, 0, 0));

        StringBuilder sb = new StringBuilder();
        Map<String, String> snap = Boot.snapshot();
        if (snap.isEmpty()) {
            sb.append("缓存：（空，连接建立后才有）");
        } else {
            sb.append("缓存到断开为止：\n");
            for (Map.Entry<String, String> e : snap.entrySet()) {
                sb.append("  ").append(e.getKey()).append(" → ").append(e.getValue()).append('\n');
            }
        }
        c.addView(Ui.text(this, sb.toString().trim(), 11f, Ui.MUTED),
                Ui.lp(this, -1, -2, 0, 8, 0, 0));
        return c;
    }

    private void probe(String domain) {
        final String d = domain == null ? "" : domain.trim();
        if (d.length() == 0) return;
        final String ip = bootIpField.getText().toString().trim();
        if (ip.length() == 0) {
            Ui.toast(this, "先填服务器 IP");
            return;
        }
        final String mode = bootSecure ? Boot.SECURE : Boot.PLAIN;
        final int p = port(bootPortField.getText().toString());
        final String sni = bootSniField.getText().toString().trim();
        Ui.toast(this, "查询中…");
        new Thread(() -> {
            long t0 = System.currentTimeMillis();
            String got = Boot.test(d, mode, ip, p, sni);
            long ms = System.currentTimeMillis() - t0;
            final String msg = got == null
                    ? d + " 解析失败（" + ms + " ms）\n换明文模式，或检查 IP / 端口 / SNI。"
                    : d + " → " + got + "（" + ms + " ms）";
            runOnUiThread(() -> Ui.info(DnsActivity.this, "Bootstrap 解析", msg));
        }).start();
    }

    /* ------------------------------------------------------------- dns path */

    /** 把「当前配置下 DNS 到底怎么走」摊开写，省得靠猜。 */
    private LinearLayout pathCard(Store.Settings s) {
        LinearLayout c = Ui.card(this);
        c.addView(Ui.label(this, "DNS 走向（当前配置）"));

        Profile p = Store.I.selected();
        boolean inject = p != null && Conf.leadIsInject(p);
        String policy = p == null ? Profile.DNS_PROXY : p.effectiveDnsPolicy();
        boolean proxy = Profile.DNS_PROXY.equals(policy);
        boolean direct = Profile.DNS_DIRECT.equals(policy);

        StringBuilder sb = new StringBuilder();
        sb.append("链路：").append(inject ? "注入（HTTP CONNECT 隧道，只能走 TCP）" : "普通出站").append('\n');
        sb.append("53 规则：").append(proxy
                ? "交给 xray 内置 DNS（dns-out）应答，应用拿不到真实解析器"
                : direct ? "原样发到真实服务器（会直连）" : "丢弃").append('\n');

        if (!proxy) {
            sb.append("上游：策略不是代理，xray 自己的查询也不走隧道\n");
        } else if (inject) {
            sb.append("上游 UDP/53：代理不了 —— HTTP 出站只支持 TCP，"
                    + "查询会被拒绝，再按服务器列表回退到下一台；没有下一台就解析失败\n");
            sb.append("上游 TCP/53：走隧道（网关要放行 53）\n");
            sb.append("上游 DoT/853：走隧道（网关要放行 853）\n");
            sb.append("上游 DoH/443：走隧道；URL 写域名时，域名本身由注入器的 bootstrap 解析\n");
        } else {
            sb.append("上游 UDP / TCP / DoT / DoH：都按同一策略走出站\n");
        }
        sb.append("注入器自身 bootstrap（节点里的 dns_url / dns_ip）：直连，不经过隧道\n");
        sb.append("自定义 Bootstrap DNS：").append(s.bootEnabled ? "开启，只用于首次解析" : "未启用");
        c.addView(Ui.text(this, sb.toString().trim(), 11.5f, Ui.MUTED),
                Ui.lp(this, -1, -2, 0, 6, 0, 0));
        return c;
    }

    /* ---------------------------------------------------------------- pieces */

    private void leave() {
        boolean same = !dirty
                && remoteField.getText().toString().trim().equals(Store.I.settings.dnsRemote)
                && domesticField.getText().toString().trim().equals(Store.I.settings.dnsDomestic)
                && bootIpField.getText().toString().trim().equals(Store.I.settings.bootIp)
                && bootSniField.getText().toString().trim().equals(Store.I.settings.bootSni)
                && port(bootPortField.getText().toString()) == Store.I.settings.bootPort;
        if (same) {
            finish();
            return;
        }
        Ui.confirm(this, "放弃这次修改？", "DNS 的改动还没保存。", new Runnable() {
            public void run() {
                finish();
            }
        });
    }

    @Override
    public void onBackPressed() {
        leave();
    }

    private static int port(String v) {
        try {
            int n = Integer.parseInt(v.trim());
            return n > 0 && n < 65536 ? n : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private LinearLayout.LayoutParams block() {
        return Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                0, 0, 0, Ui.dp(this, 10));
    }

    /** 预置按钮：固定每行 3 个等宽，行间 6dp。
     *  不用 FlowLayout —— 它自己算换行和行高，父容器宽度一变最后一行就超出自身高度，
     *  被卡片默认的 clipChildren 裁掉，看起来就是"边框被下一层盖住"。等宽行没有测量逻辑。 */
    private LinearLayout pillRows(final EditText field, String[][] items) {
        LinearLayout col = Ui.column(this);
        for (int i = 0; i < items.length; i += 3) {
            LinearLayout row = Ui.row(this);
            for (int k = 0; k < 3; k++) {
                int idx = i + k;
                if (idx < items.length) {
                    TextView t = preset(items[idx][0], items[idx][1], field);
                    t.setLayoutParams(Ui.wp(this, -2, 1, k == 0 ? 0 : 6, 0, 0, 0));
                    row.addView(t);
                } else {
                    View pad = new View(this);
                    pad.setLayoutParams(Ui.wp(this, -2, 1, 0, 0, 0, 0));
                    row.addView(pad);
                }
            }
            col.addView(row, Ui.lp(this, -1, -2, 0, i == 0 ? 0 : 6, 0, 0));
        }
        return col;
    }

    private TextView preset(String label, final String value, final EditText target) {
        TextView t = Ui.pill(this, label, 0xFFF1F3F6, Ui.INK);
        t.setTextSize(11.5f);
        t.setOnClickListener(v -> {
            target.setText(value);
            Ui.toast(this, "已填入，记得点保存");
        });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = Ui.dp(this, 6);
        t.setLayoutParams(lp);
        return t;
    }

    private TextView bootPreset(String label, final String ip, final String sni) {
        TextView t = Ui.pill(this, label, 0xFFF1F3F6, Ui.INK);
        t.setTextSize(11.5f);
        t.setOnClickListener(v -> {
            bootIpField.setText(ip);
            bootSniField.setText(sni);
            bootPortField.setText("");
            dirty = true;
            Ui.toast(this, "已填入，记得点保存");
        });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = Ui.dp(this, 6);
        t.setLayoutParams(lp);
        return t;
    }
}
