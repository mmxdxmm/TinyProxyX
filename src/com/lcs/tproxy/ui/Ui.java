package com.lcs.tproxy.ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/** Tiny UI toolkit: everything is built in code, no xml layouts, no androidx. */
public class Ui {

    public static final int WHITE = 0xFFFFFFFF;
    public static final int BG = 0xFFF5F6F8;
    public static final int INK = 0xFF12161C;
    public static final int MUTED = 0xFF8A93A0;
    public static final int ACCENT = 0xFF2F6BFF;
    public static final int ACCENT_SOFT = 0xFFEAF0FF;
    public static final int DANGER = 0xFFE5484D;
    public static final int OK = 0xFF10A05A;
    public static final int WARN = 0xFFE8A33D;
    public static final int LINE = 0xFFE9ECF1;

    public interface Sink {
        void run(String value);
    }

    public interface Pick {
        void on(int index);
    }

    public static int dp(Context c, float v) {
        return (int) (v * c.getResources().getDisplayMetrics().density + 0.5f);
    }

    public static GradientDrawable round(int color, float radiusPx) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(radiusPx);
        return g;
    }

    public static GradientDrawable roundStroke(int color, float radiusPx, int strokeColor, int strokeW) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(radiusPx);
        g.setStroke(strokeW, strokeColor);
        return g;
    }

    public static LinearLayout column(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    public static LinearLayout row(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL);
        return l;
    }

    public static LinearLayout.LayoutParams lp(int w, int h) {
        return new LinearLayout.LayoutParams(w, h);
    }

    /** 上面那个 6 参 lp 吃的是像素，边距一律用下面这个 dp 版本。 */
    public static LinearLayout.LayoutParams lp(int w, int h, int l, int t, int r, int b) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w, h);
        p.setMargins(l, t, r, b);
        return p;
    }

    /** (w,h) + dp 边距。 */
    public static LinearLayout.LayoutParams lp(Context c, int w, int h, int l, int t, int r, int b) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w, h);
        p.setMargins(dp(c, l), dp(c, t), dp(c, r), dp(c, b));
        return p;
    }

    /**
     * 宽度 0 + weight：在 LinearLayout 里按权重吃剩余宽度（高度照传，-2 是 wrap）。
     * 横向一行里「左边留标签、右边给箭头」必须用它 —— 只设 width=0 会变成 0 宽，字直接看不见。
     */
    public static LinearLayout.LayoutParams wp(Context c, int h, int weight, int l, int t, int r, int b) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0, h);
        p.weight = weight;
        p.setMargins(dp(c, l), dp(c, t), dp(c, r), dp(c, b));
        return p;
    }

    /** 整行宽 + 上下 dp 间距，卡片竖排专用。 */
    public static LinearLayout.LayoutParams block(Context c, int above, int below) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.setMargins(0, dp(c, above), 0, dp(c, below));
        return p;
    }

    public static LinearLayout card(Context c) {
        LinearLayout l = column(c);
        l.setBackgroundDrawable(roundStroke(WHITE, dp(c, 16), LINE, dp(c, 1)));
        int p = dp(c, 16);
        l.setPadding(p, p, p, p);
        /* 卡片里的按钮条比卡片窄一圈，别让裁剪把最后一行/描边切掉 */
        l.setClipToPadding(false);
        l.setClipChildren(false);
        return l;
    }

    public static TextView text(Context c, String s, float sp, int color) {
        TextView t = new TextView(c);
        t.setText(s == null ? "" : s);
        t.setTextSize(sp);
        t.setTextColor(color);
        return t;
    }

    public static TextView title(Context c, String s) {
        TextView t = text(c, s, 16f, INK);
        t.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        return t;
    }

    public static TextView label(Context c, String s) {
        return text(c, s, 12f, MUTED);
    }

    public static EditText field(Context c, String hint, String value) {
        EditText e = new EditText(c);
        e.setHint(hint);
        e.setText(value == null ? "" : value);
        e.setTextSize(14f);
        e.setTextColor(INK);
        e.setHintTextColor(0xFFB6BEC9);
        e.setBackgroundDrawable(roundStroke(0xFFFBFCFD, dp(c, 10), LINE, dp(c, 1)));
        int p = dp(c, 10);
        e.setPadding(p, dp(c, 7), p, dp(c, 7));
        e.setSingleLine(true);
        /* 统一最小高度，和 pill 放在同一行时不会一高一矮，也不会贴在一起 */
        e.setMinHeight(dp(c, 42));
        return e;
    }

    public static EditText area(Context c, String hint, String value, int lines) {
        EditText e = field(c, hint, value);
        e.setSingleLine(false);
        e.setMinLines(lines);
        e.setGravity(Gravity.TOP | Gravity.START);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        /* 多行输入框在 ScrollView 里要自己吃竖直滑动，否则一滑整页跟着动 */
        e.setOnTouchListener(new View.OnTouchListener() {
            public boolean onTouch(View v, android.view.MotionEvent ev) {
                if (ev.getActionMasked() == android.view.MotionEvent.ACTION_DOWN) {
                    v.getParent().requestDisallowInterceptTouchEvent(true);
                } else if (ev.getActionMasked() == android.view.MotionEvent.ACTION_UP
                        || ev.getActionMasked() == android.view.MotionEvent.ACTION_CANCEL) {
                    v.getParent().requestDisallowInterceptTouchEvent(false);
                }
                return false;
            }
        });
        return e;
    }

    /** 次要按钮用的底色。凡是这个颜色的 pill 都画成"白底 + 细边"，
     *  否则放在白色卡片上就是一块白，完全看不出是可点的按钮。 */
    public static final int NEUTRAL = 0xFFF1F3F6;
    public static final int EDGE = 0xFFD2D9E2;

    /** pill / 开关共用的底：给 NEUTRAL 补一圈边，其它颜色照旧。 */
    public static GradientDrawable chipBg(Context c, int bg) {
        if (bg == NEUTRAL) {
            return roundStroke(WHITE, dp(c, 22), EDGE, Math.max(1, dp(c, 1)));
        }
        return round(bg, dp(c, 22));
    }

    public static TextView pill(Context c, String label, int bg, int fg) {
        TextView t = text(c, label, 13f, fg);
        t.setGravity(Gravity.CENTER);
        /* 单行 + 省略：放在窄容器里也不会被压成"一列字" */
        t.setSingleLine(true);
        t.setEllipsize(android.text.TextUtils.TruncateAt.END);
        t.setPadding(dp(c, 14), dp(c, 10), dp(c, 14), dp(c, 10));
        t.setMinHeight(dp(c, 42));
        t.setBackgroundDrawable(chipBg(c, bg));
        t.setClickable(true);
        return t;
    }

    /** 一排等宽按钮的位置参数：一排几个各占一份，同一行，不会因为文字长短挤下去。 */
    public static LinearLayout.LayoutParams share(Context c, int l, int r) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        p.weight = 1f;
        p.setMargins(dp(c, l), 0, dp(c, r), 0);
        return p;
    }

    public static View divider(Context c) {
        View v = new View(c);
        v.setBackgroundColor(LINE);
        v.setLayoutParams(lp(ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, dp(c, 1))));
        return v;
    }

    public static void gap(View v, int h) {
        v.setLayoutParams(lp(ViewGroup.LayoutParams.MATCH_PARENT, dp(v.getContext(), h)));
    }

    public static void toast(Context c, String s) {
        Toast.makeText(c, s, Toast.LENGTH_SHORT).show();
    }

    public static void lightStatus(Activity a) {
        try {
            Window w = a.getWindow();
            if (Build.VERSION.SDK_INT >= 21) {
                w.setStatusBarColor(WHITE);
                w.setNavigationBarColor(WHITE);
            }
            if (Build.VERSION.SDK_INT >= 23) {
                View d = w.getDecorView();
                d.setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                        | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
            }
        } catch (Exception ignored) {
        }
    }

    public static ScrollView page(Activity a, LinearLayout content) {
        ScrollView sv = new ScrollView(a);
        sv.setFillViewport(true);
        sv.setBackgroundColor(BG);
        content.setOrientation(LinearLayout.VERTICAL);
        int p = dp(a, 14);
        content.setPadding(p, p, p, dp(a, 28));
        sv.addView(content, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        return sv;
    }

    public static void inputDialog(Context c, String title, String def, final Sink sink) {
        final EditText e = field(c, "", def);
        LinearLayout box = column(c);
        int p = dp(c, 16);
        box.setPadding(p, dp(c, 8), p, 0);
        box.addView(e);
        new AlertDialog.Builder(c).setTitle(title).setView(box)
                .setPositiveButton("确定", (d, w) -> sink.run(e.getText().toString()))
                .setNegativeButton("取消", null).show();
    }

    public static void promptDialog(Context c, String title, String def, final Sink sink) {
        final EditText e = area(c, "", def, 8);
        e.setSingleLine(false);
        LinearLayout box = column(c);
        int p = dp(c, 12);
        box.setPadding(p, dp(c, 8), p, 0);
        box.addView(e, lp(ViewGroup.LayoutParams.MATCH_PARENT, dp(c, 220)));
        new AlertDialog.Builder(c).setTitle(title).setView(box)
                .setPositiveButton("确定", (d, w) -> sink.run(e.getText().toString()))
                .setNegativeButton("取消", null).show();
    }

    public static void confirm(Context c, String title, String msg, final Runnable ok) {
        new AlertDialog.Builder(c).setTitle(title).setMessage(msg)
                .setPositiveButton("确定", (d, w) -> ok.run())
                .setNegativeButton("取消", null).show();
    }

    public static void choose(Context c, String title, String[] items, final Pick pick) {
        new AlertDialog.Builder(c).setTitle(title)
                .setItems(items, (d, w) -> pick.on(w)).show();
    }

    public static void info(Context c, String title, String msg) {
        new AlertDialog.Builder(c).setTitle(title).setMessage(msg)
                .setPositiveButton("知道了", null).show();
    }

    public static int alpha(int color, float a) {
        return Color.argb((int) (a * 255), Color.red(color), Color.green(color), Color.blue(color));
    }
}
