package com.lcs.tproxy.ui;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;

/** Wrapping row: children flow left to right and drop to the next line instead of being squeezed.
 *  Used for every button strip so labels never get crushed on narrow screens.
 *  默认 8dp 间距：以前默认 0，凡是 `new FlowLayout(this)` 的按钮条都会贴在一起。 */
public class FlowLayout extends ViewGroup {

    public static final float GAP_DP = 10f;

    private final int hGap;
    private final int vGap;

    public FlowLayout(Context c) {
        this(c, pad(c), pad(c));
    }

    private static int pad(Context c) {
        return Math.round(GAP_DP * c.getResources().getDisplayMetrics().density);
    }

    public FlowLayout(Context c, int hGap, int vGap) {
        super(c);
        this.hGap = hGap;
        this.vGap = vGap;
    }

    public FlowLayout(Context c, AttributeSet a) {
        super(c, a);
        this.hGap = pad(c);
        this.vGap = pad(c);
    }

    @Override
    protected LayoutParams generateDefaultLayoutParams() {
        return new MarginLayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
    }

    @Override
    public LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new MarginLayoutParams(getContext(), attrs);
    }

    @Override
    protected LayoutParams generateLayoutParams(LayoutParams p) {
        return new MarginLayoutParams(p);
    }

    @Override
    protected boolean checkLayoutParams(LayoutParams p) {
        return p instanceof MarginLayoutParams;
    }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        /* 万一被 UNSPECIFIED 量（以前没防过），avail=0 会把每个按钮都挤成 0 宽，整条看不见 */
        int width = MeasureSpec.getMode(widthSpec) == MeasureSpec.UNSPECIFIED
                ? 1 << 16 : MeasureSpec.getSize(widthSpec);
        int avail = Math.max(0, width - getPaddingLeft() - getPaddingRight());
        int x = 0;
        int y = 0;
        int rowH = 0;
        int maxW = 0;
        int count = getChildCount();
        for (int i = 0; i < count; i++) {
            View ch = getChildAt(i);
            if (ch.getVisibility() == GONE) continue;
            MarginLayoutParams lp = (MarginLayoutParams) ch.getLayoutParams();
            /* 边界：单个按钮不许比自己一行还宽，否则它会顶出卡片。
               pill 都是单行 + 省略号，所以这里给 AT_MOST 就会自己缩，不会截到看不见。 */
            int inner = Math.max(0, avail - lp.leftMargin - lp.rightMargin);
            measureChildWithMargins(ch,
                    MeasureSpec.makeMeasureSpec(inner, MeasureSpec.AT_MOST), 0,
                    heightSpec, 0);
            int cw = ch.getMeasuredWidth() + lp.leftMargin + lp.rightMargin;
            int chh = ch.getMeasuredHeight() + lp.topMargin + lp.bottomMargin;
            boolean wraps = x > 0 && x + cw > avail;
            if (wraps) {
                x = 0;
                y += rowH + vGap;
                rowH = 0;
            }
            x += cw + hGap;
            rowH = Math.max(rowH, chh);
            maxW = Math.max(maxW, x - hGap);
        }
        int h = y + rowH + getPaddingTop() + getPaddingBottom();
        /* 量出来的宽度不能超过父给的可用宽度，否则 getView 会画到卡片外面 */
        int want = Math.min(maxW, avail) + getPaddingLeft() + getPaddingRight();
        setMeasuredDimension(
                resolveSize(Math.max(want, getSuggestedMinimumWidth()), widthSpec),
                resolveSize(h, heightSpec));
    }

    @Override
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        int avail = getWidth() - getPaddingLeft() - getPaddingRight();
        int x = getPaddingLeft();
        int y = getPaddingTop();
        int rowH = 0;
        int count = getChildCount();
        for (int i = 0; i < count; i++) {
            View ch = getChildAt(i);
            if (ch.getVisibility() == GONE) continue;
            MarginLayoutParams lp = (MarginLayoutParams) ch.getLayoutParams();
            int cw = Math.min(ch.getMeasuredWidth(), Math.max(0, avail - lp.leftMargin - lp.rightMargin));
            int chh = ch.getMeasuredHeight();
            int cellW = cw + lp.leftMargin + lp.rightMargin;
            boolean wraps = x > getPaddingLeft() && (x - getPaddingLeft()) + cellW > avail;
            if (wraps) {
                x = getPaddingLeft();
                y += rowH + vGap;
                rowH = 0;
            }
            int left = x + lp.leftMargin;
            ch.layout(left, y + lp.topMargin, left + cw, y + lp.topMargin + chh);
            x += cellW + hGap;
            rowH = Math.max(rowH, chh + lp.topMargin + lp.bottomMargin);
        }
    }
}
