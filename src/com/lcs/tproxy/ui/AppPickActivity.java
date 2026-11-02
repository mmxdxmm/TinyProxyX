package com.lcs.tproxy.ui;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/** Per-app split tunnelling: allow list or deny list for the selected profile. */
public class AppPickActivity extends Activity {

    private LinearLayout box;
    /** Store 里的真身，只有点「保存」才覆盖 */
    private Profile src;
    /** 草稿：勾选、黑白名单切换都只改它 */
    private Profile profile;
    private boolean dirty;
    private TextView summary;
    private TextView modePill;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Ui.lightStatus(this);
        src = Store.I.selected();
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
        TextView title = Ui.text(this, "分应用代理", 17f, Ui.INK);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setGravity(android.view.Gravity.CENTER);
        bar.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView done = Ui.text(this, "保存", 15f, Ui.ACCENT);
        done.setOnClickListener(v -> commit());
        bar.addView(done);
        root.addView(bar);

        LinearLayout content = Ui.column(this);
        LinearLayout top = Ui.card(this);
        summary = Ui.text(this, "", 12.5f, Ui.MUTED);
        top.addView(summary);
        LinearLayout modeRow = Ui.row(this);
        modeRow.setPadding(0, Ui.dp(this, 8), 0, 0);
        TextView mode = Ui.pill(this, "", 0xFFF1F3F6, Ui.INK);
        modePill = mode;
        modeRow.addView(mode);
        top.addView(modeRow);
        mode.setOnClickListener(v -> {
            profile.perAppAllowMode = !profile.perAppAllowMode;
            dirty = true;
            render();
        });
        content.addView(top, Ui.lp(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 0, 0, 0, Ui.dp(this, 10)));

        box = Ui.column(this);
        content.addView(box);
        root.addView(Ui.page(this, content), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private void commit() {
        src.takeFrom(profile);
        Store.I.save();
        dirty = false;
        com.lcs.tproxy.core.Control.disconnectSoon(this);
        Ui.toast(this, "分应用代理已保存，运行配置已断开");
        finish();
    }

    private void leave() {
        if (!dirty) {
            finish();
            return;
        }
        Ui.confirm(this, "放弃这次修改？", "勾选的应用和黑白名单还没保存。", new Runnable() {
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
        Profile p = profile;
        modePill.setText(p.perAppAllowMode ? "切换为黑名单" : "切换为白名单");
        summary.setText((p.perAppEnabled ? "已启用" : "未启用")
                + " · 当前模式：" + (p.perAppAllowMode ? "白名单（只代理选中的应用）" : "黑名单（排除选中的应用）")
                + " · 已选 " + p.apps.size() + " 个");
        box.removeAllViews();

        final PackageManager pm = getPackageManager();
        Intent main = new Intent(Intent.ACTION_MAIN);
        main.addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> infos = pm.queryIntentActivities(main, 0);
        List<ResolveInfo> list = new ArrayList<ResolveInfo>(infos);
        Collections.sort(list, new Comparator<ResolveInfo>() {
            public int compare(ResolveInfo a, ResolveInfo b) {
                return pm.getApplicationLabel(a.activityInfo.applicationInfo).toString()
                        .compareToIgnoreCase(pm.getApplicationLabel(b.activityInfo.applicationInfo).toString());
            }
        });
        for (ResolveInfo ri : list) {
            final String pkg = ri.activityInfo.packageName;
            if (pkg.equals(getPackageName())) continue;
            LinearLayout row = Ui.row(this);
            row.setPadding(0, Ui.dp(this, 6), 0, Ui.dp(this, 6));
            LinearLayout names = Ui.column(this);
            names.addView(Ui.text(this, pm.getApplicationLabel(ri.activityInfo.applicationInfo).toString(),
                    13.5f, Ui.INK));
            names.addView(Ui.text(this, pkg, 10.5f, Ui.MUTED));
            row.addView(names, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            CheckBox cb = new CheckBox(this);
            cb.setChecked(profile.apps.contains(pkg));
            cb.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                public void onCheckedChanged(CompoundButton b, boolean v) {
                    if (v) {
                        if (!profile.apps.contains(pkg)) profile.apps.add(pkg);
                    } else profile.apps.remove(pkg);
                    profile.perAppEnabled = !profile.apps.isEmpty();
                    dirty = true;
                    summary.setText((profile.perAppEnabled ? "已启用" : "未启用")
                            + " · " + (profile.perAppAllowMode ? "白名单" : "黑名单")
                            + " · 已选 " + profile.apps.size() + " 个");
                }
            });
            row.addView(cb);
            box.addView(row);
        }
    }
}
