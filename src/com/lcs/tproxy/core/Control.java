package com.lcs.tproxy.core;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.root.Root;
import com.lcs.tproxy.vpn.RootService;
import com.lcs.tproxy.vpn.TunService;

import java.util.ArrayList;
import java.util.List;

/** Glue between the UI and the two runtime modes. Every start/stop invalidates older workers. */
public class Control {

    public interface Watcher {
        void onChanged();
    }

    public static final String EXTRA_GENERATION = "generation";
    private static final List<Watcher> watchers = new ArrayList<Watcher>();
    private static final Object LOCK = new Object();
    private static long generation;
    private static volatile Thread stopWorker;
    public static volatile String state = "idle";
    public static volatile String message = "";

    public static void add(Watcher w) {
        synchronized (watchers) {
            if (!watchers.contains(w)) watchers.add(w);
        }
    }

    public static void remove(Watcher w) {
        synchronized (watchers) {
            watchers.remove(w);
        }
    }

    public static void changed() {
        for (Watcher w : snapshot()) {
            try {
                w.onChanged();
            } catch (Exception ignored) {
            }
        }
    }

    private static List<Watcher> snapshot() {
        synchronized (watchers) {
            return new ArrayList<Watcher>(watchers);
        }
    }

    /** Starting is owned too: saving settings during boot must cancel that boot. */
    public static boolean running() {
        return "starting".equals(state) || "running".equals(state) || Engine.I.isRunning();
    }

    public static boolean busy() {
        return "starting".equals(state) || "stopping".equals(state);
    }

    public static boolean isRootMode() {
        return !"vpn".equals(Store.I.settings.mode);
    }

    public static boolean current(long id) {
        synchronized (LOCK) {
            return id != 0 && id == generation && "starting".equals(state);
        }
    }

    public static boolean finishStart(long id, String profileName, boolean root) {
        synchronized (LOCK) {
            if (id != generation || !"starting".equals(state)) return false;
            state = "running";
            message = (root ? "热点 · " : "VPN · ") + profileName;
        }
        changed();
        return true;
    }

    public static boolean failStart(long id, String error) {
        synchronized (LOCK) {
            if (id != generation) return false;
            state = "idle";
            message = error;
        }
        changed();
        return true;
    }

    /** Start with the configured mode; returns null on success or an error message. */
    public static String start(Context c) {
        final long id;
        final boolean root;
        Profile p = Store.I.selected();
        if (p == null || p.chain.isEmpty()) return "没有可用配置";
        synchronized (LOCK) {
            if (!"idle".equals(state)) return "正在" + ("stopping".equals(state) ? "停止，请稍候" : "启动，请勿重复点击");
            root = isRootMode();
            if (root && !Root.hasRoot()) return "未获得 root 权限，无法使用 ROOT 模式";
            id = ++generation;
            state = "starting";
            message = root ? "正在启动 ROOT 通道" : "正在启动 VPN";
        }
        changed();
        try {
            Intent i = new Intent(c, root ? RootService.class : TunService.class);
            i.setAction(root ? RootService.ACTION_START : TunService.ACTION_START);
            i.putExtra(EXTRA_GENERATION, id);
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i);
            else c.startService(i);
            return null;
        } catch (Throwable e) {
            failStart(id, "启动服务失败：" + e.getClass().getSimpleName());
            return message;
        }
    }

    /** Invalidate first, then do blocking native/root cleanup off the UI thread. */
    public static void stop(final Context c) {
        final Context app = c.getApplicationContext();
        synchronized (LOCK) {
            if ("stopping".equals(state) && stopWorker != null && stopWorker.isAlive()) return;
            ++generation;
            state = "stopping";
            message = "正在断开并清理";
        }
        changed();
        stopWorker = new Thread(new Runnable() {
            public void run() {
                sendStop(app, TunService.class, TunService.ACTION_STOP);
                sendStop(app, RootService.class, RootService.ACTION_STOP);
                Engine.I.stopTun();
                Engine.I.stop(app);
                boolean clean = true;
                if (Store.I.settings.rootArmed || "root".equals(Engine.I.mode)) {
                    clean = Root.cleanup(app);
                    Store.I.settings.rootArmed = !clean;
                    Store.I.save();
                }
                synchronized (LOCK) {
                    state = "idle";
                    message = clean ? "已停止" : "核心已停止，但 root 规则清理失败；下次打开 App 会重试";
                }
                Engine.I.log(message);
                changed();
            }
        }, "proxy-stop");
        stopWorker.start();
    }

    private static void sendStop(Context c, Class<?> cls, String action) {
        try {
            c.startService(new Intent(c, cls).setAction(action));
        } catch (Throwable e) {
            Engine.I.log("停止服务投递失败（后台限制？），核心仍会由统一停止线程清理");
        }
    }

    public static String bindActivity(Activity a) {
        return null;
    }

    private static android.os.Handler handler;
    private static Runnable pending;

    /** All runtime-affecting saves converge here. Debounce bursts, including changes during boot. */
    public static void disconnectSoon(final Context c) {
        if (!running()) return;
        if (handler == null) handler = new android.os.Handler(android.os.Looper.getMainLooper());
        if (pending != null) handler.removeCallbacks(pending);
        final Context app = c.getApplicationContext();
        pending = new Runnable() {
            public void run() {
                pending = null;
                disconnect(app);
            }
        };
        handler.postDelayed(pending, 700);
    }

    /** Stop once; never resurrect an older connection. */
    public static void disconnect(final Context c) {
        if (!running() && !busy()) return;
        Engine.I.log("配置已改动，断开当前连接（不自动重连）");
        stop(c);
    }

    /** Failed cleanup stays armed, including the sweep itself. */
    public static void sweepStaleRoot(final Context c) {
        final Store.Settings s = Store.I.settings;
        if (!s.rootArmed || running() || busy()) return;
        new Thread(new Runnable() {
            public void run() {
                boolean clean = Root.cleanup(c);
                Engine.I.killRootStrays(c);
                s.rootArmed = !clean;
                Store.I.save();
                Engine.I.log(clean ? "清理了上次残留的热点规则" : "上次热点规则仍未清干净，已保留重试标记");
            }
        }, "root-sweep").start();
    }
}
