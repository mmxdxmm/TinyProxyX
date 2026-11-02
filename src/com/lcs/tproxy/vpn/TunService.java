package com.lcs.tproxy.vpn;

import android.app.Notification;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import com.lcs.tproxy.core.Control;
import com.lcs.tproxy.core.Engine;
import com.lcs.tproxy.core.Notify;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;

public class TunService extends VpnService {

    public static final String ACTION_START = "com.lcs.tproxy.START_VPN";
    public static final String ACTION_STOP = "com.lcs.tproxy.STOP_VPN";
    public static final String ADDR = "26.26.26.2";
    public static final int MTU = 1500;

    private ParcelFileDescriptor tun;
    private long generation;
    private boolean expectedStop;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? "" : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            closeLocal();
            return START_NOT_STICKY;
        }
        generation = intent.getLongExtra(Control.EXTRA_GENERATION, 0);
        if (!Control.current(generation)) {
            closeLocal();
            return START_NOT_STICKY;
        }
        Notification n = Notify.build(this, "TinyProxy X", "VPN 正在连接", true);
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(Notify.ID, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(Notify.ID, n);
            }
        } catch (Throwable e) {
            Control.failStart(generation, "VPN 前台服务启动失败：" + e.getClass().getSimpleName());
            Control.stop(this);
            closeLocal();
            return START_NOT_STICKY;
        }
        new Thread(new Runnable() {
            public void run() {
                boot(generation);
            }
        }, "vpn-boot").start();
        return START_NOT_STICKY;
    }

    private void boot(long id) {
        if (!Control.current(id)) return;
        String err = Engine.I.start(this, false, id);
        if (err != null) {
            fail(id, err);
            return;
        }
        if (!Control.current(id)) return;
        ParcelFileDescriptor created = null;
        try {
            Profile p = Store.I.selected();
            boolean capV6 = p == null || p.captureV6();
            Builder b = new Builder();
            b.setMtu(MTU);
            b.setSession("TinyProxy X");
            b.addAddress(Engine.NETIF, 32);
            b.addRoute("0.0.0.0", 0);
            b.addDnsServer("1.1.1.1");
            b.addDnsServer("8.8.8.8");
            if (capV6) {
                b.addAddress("fd00:26:26:26::2", 64);
                b.addRoute("::", 0);
            }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            b.addDisallowedApplication(getPackageName());
            if (p != null && p.perAppEnabled) {
                for (String pkg : p.apps) {
                    try {
                        if (p.perAppAllowMode) b.addAllowedApplication(pkg);
                        else b.addDisallowedApplication(pkg);
                    } catch (PackageManager.NameNotFoundException ignored) {
                    }
                }
            }
            b.setBlocking(false);
            created = b.establish();
            if (created == null) {
                fail(id, "VPN 授权被拒绝");
                return;
            }
            tun = created;
            if (!Control.current(id)) {
                closeLocal();
                return;
            }
            int fd;
            try {
                android.system.Os.fcntlInt(created.getFileDescriptor(), android.system.OsConstants.F_SETFD, 0);
            } catch (Throwable ignored) {
            }
            try {
                fd = created.getFd();
            } catch (Throwable t) {
                fd = -1;
            }
            if (fd < 0) {
                fail(id, "拿不到 tun fd");
                return;
            }
            String e2 = Engine.I.startTun(this, created, fd, false);
            if (e2 != null) {
                fail(id, e2);
                return;
            }
            if (!Control.finishStart(id, p == null ? "" : p.name, false)) {
                closeLocal();
                return;
            }
            Notification connected = Notify.build(this, "TinyProxy X", "VPN 模式已连接", true);
            ((android.app.NotificationManager) getSystemService(NOTIFICATION_SERVICE)).notify(Notify.ID, connected);
        } catch (Throwable e) {
            if (created != null && tun == null) {
                try { created.close(); } catch (Exception ignored) { }
            }
            fail(id, e.getMessage() == null ? e.toString() : e.getMessage());
        }
    }

    private void fail(long id, String msg) {
        if (Control.failStart(id, msg)) {
            Engine.I.stopTun();
            Engine.I.stopIfOwner(this, generation);
        }
        closeLocal();
    }

    /** Local resources only. Global processes belong to Control.stop(), not an obsolete Service. */
    private void closeLocal() {
        expectedStop = true;
        try {
            if (tun != null) tun.close();
        } catch (Exception ignored) {
        }
        tun = null;
        stopForeground(true);
        stopSelf();
    }

    @Override
    public void onRevoke() {
        Control.stop(this);
        closeLocal();
    }

    @Override
    public void onDestroy() {
        closeLocal();
        if (!expectedStop && !Control.busy() && Control.running()) Control.stop(this);
        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        Engine.I.log("任务卡片被移除，停止 VPN");
        Control.stop(this);
        closeLocal();
        super.onTaskRemoved(rootIntent);
    }
}
