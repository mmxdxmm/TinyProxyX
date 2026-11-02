package com.lcs.tproxy.ui;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.lcs.tproxy.core.Engine;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;

/** Log viewer: newest on top, level + ring size controls, export. */
public class LogActivity extends Activity {

    private LinearLayout list;
    private TextView status;
    private final Handler tick = new Handler(Looper.getMainLooper());
    private boolean alive = true;
    private long lastVersion = -1;

    private final Runnable refresh = new Runnable() {
        public void run() {
            if (!alive) return;
            render();
            tick.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Ui.lightStatus(this);
        setContentView(build());
        tick.post(refresh);
    }

    @Override
    protected void onDestroy() {
        alive = false;
        tick.removeCallbacks(refresh);
        super.onDestroy();
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
        TextView title = Ui.text(this, "运行日志", 17f, Ui.INK);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setGravity(android.view.Gravity.CENTER);
        bar.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView clear = Ui.text(this, "清空", 15f, Ui.ACCENT);
        clear.setOnClickListener(v -> {
            Engine.I.clearLog();
            render();
        });
        bar.addView(clear);
        root.addView(bar);

        LinearLayout content = Ui.column(this);
        LinearLayout ctrl = Ui.card(this);
        status = Ui.text(this, "", 11.5f, Ui.MUTED);
        ctrl.addView(status);

        LinearLayout lvlRow = Ui.row(this);
        lvlRow.setPadding(0, Ui.dp(this, 8), 0, 0);
        lvlRow.addView(Ui.text(this, "等级", 12f, Ui.MUTED),
                new LinearLayout.LayoutParams(Ui.dp(this, 46), ViewGroup.LayoutParams.WRAP_CONTENT));
        TextView lvl = Ui.pill(this, curLevel(), 0xFFF1F3F6, Ui.INK);
        lvl.setOnClickListener(v -> Ui.choose(this, "日志等级",
                new String[]{"debug", "info", "warning", "error"}, i -> {
                    Profile sel = Store.I.selected();
                    if (sel != null) {
                        sel.logLevel = new String[]{"debug", "info", "warning", "error"}[i];
                        Store.I.save();
                    }
                    lvl.setText(curLevel());
                    com.lcs.tproxy.core.Control.disconnectSoon(this);
                    Ui.toast(this, "已保存，运行配置已断开");
                }));
        lvlRow.addView(lvl);
        ctrl.addView(lvlRow);

        LinearLayout sizeRow = Ui.row(this);
        sizeRow.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 4));
        sizeRow.addView(Ui.text(this, "条数", 12f, Ui.MUTED),
                new LinearLayout.LayoutParams(Ui.dp(this, 46), ViewGroup.LayoutParams.WRAP_CONTENT));
        TextView size = Ui.pill(this, Store.I.settings.logLines + " 条", 0xFFF1F3F6, Ui.INK);
        size.setOnClickListener(v -> Ui.inputDialog(this, "保留条数（100-5000）",
                String.valueOf(Store.I.settings.logLines), s -> {
                    try {
                        int n = Integer.parseInt(s.trim());
                        Store.I.settings.logLines = Math.max(100, Math.min(5000, n));
                        Store.I.save();
                        size.setText(Store.I.settings.logLines + " 条");
                        lastVersion = -1;
                        render();
                    } catch (Exception e) {
                        Ui.toast(this, "数字无效");
                    }
                }));
        sizeRow.addView(size);
        ctrl.addView(sizeRow);

        FlowLayout ops = new FlowLayout(this, Ui.dp(this, 8), Ui.dp(this, 8));
        ops.setPadding(0, Ui.dp(this, 8), 0, 0);
        ops.addView(pill("导出为文本", () -> export()));
        ops.addView(pill("保存到应用目录", () -> save()));
        ops.addView(pill("复制全部", () -> {
            android.content.ClipboardManager cm = (android.content.ClipboardManager)
                    getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(android.content.ClipData.newPlainText("log", Engine.I.logText()));
            Ui.toast(this, "已复制");
        }));
        ctrl.addView(ops);
        content.addView(ctrl, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, Ui.dp(this, 10)));

        list = Ui.column(this);
        ScrollView sv = Ui.page(this, content);
        content.addView(list);
        root.addView(sv, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private TextView pill(String label, final Runnable r) {
        TextView t = Ui.pill(this, label, 0xFFF1F3F6, Ui.INK);
        t.setTextSize(12f);
        t.setOnClickListener(v -> r.run());
        return t;
    }

    private String curLevel() {
        Profile p = Store.I.selected();
        return p == null || p.logLevel == null ? "warning" : p.logLevel;
    }

    private void render() {
        List<String> lines = Engine.I.logLines();
        long version = Engine.I.logVersion();
        status.setText("共 " + lines.size() + " 条（最多 " + Store.I.settings.logLines
                + "）· 最新在上 · " + Engine.I.mode + " 模式");
        if (version == lastVersion) return;
        lastVersion = version;
        list.removeAllViews();
        for (String line : lines) {
            TextView t = Ui.text(this, line, 11f,
                    line.contains("direct") ? Ui.WARN
                            : line.contains("proxy") ? Ui.ACCENT
                            : line.contains("失败") || line.contains("error") ? Ui.DANGER : Ui.INK);
            t.setTypeface(android.graphics.Typeface.MONOSPACE);
            t.setPadding(0, Ui.dp(this, 3), 0, Ui.dp(this, 3));
            list.addView(t);
        }
        if (lines.isEmpty()) list.addView(Ui.text(this, "暂无日志", 12f, Ui.MUTED));
    }

    private static final int reqExport = 3001;

    private void export() {
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("text/plain");
        String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmm", java.util.Locale.US)
                .format(new java.util.Date());
        i.putExtra(Intent.EXTRA_TITLE, "TinyProxyX-log-" + stamp + ".txt");
        try {
            startActivityForResult(i, reqExport);
        } catch (Exception e) {
            String text = Engine.I.logText();
            Intent s = new Intent(Intent.ACTION_SEND);
            s.setType("text/plain");
            s.putExtra(Intent.EXTRA_SUBJECT, "TinyProxy X 日志");
            s.putExtra(Intent.EXTRA_TEXT, text);
            startActivity(Intent.createChooser(s, "导出日志"));
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == reqExport && res == RESULT_OK && data != null && data.getData() != null) {
            try {
                java.io.OutputStream out = getContentResolver().openOutputStream(data.getData());
                out.write(Engine.I.logText().getBytes("UTF-8"));
                out.flush();
                out.close();
                Ui.toast(this, "日志已导出");
            } catch (Exception e) {
                Ui.toast(this, "导出失败");
            }
        }
    }

    private void save() {
        try {
            File f = new File(getExternalFilesDir(null) == null ? getFilesDir()
                    : getExternalFilesDir(null), "tinyproxy-log.txt");
            FileOutputStream out = new FileOutputStream(f);
            out.write(Engine.I.logText().getBytes("UTF-8"));
            out.flush();
            out.close();
            Ui.info(this, "已保存", f.getAbsolutePath());
        } catch (Exception e) {
            Ui.info(this, "保存失败", e.toString());
        }
    }
}
