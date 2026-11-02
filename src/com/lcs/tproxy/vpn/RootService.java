package com.lcs.tproxy.vpn;

import android.app.Notification;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import com.lcs.tproxy.core.Control;
import com.lcs.tproxy.core.Engine;
import com.lcs.tproxy.core.Notify;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.root.Root;

import java.util.List;

/** Root mode: no tun, no VpnService. xray listens for tproxy, iptables does the steering. */
public class RootService extends Service {

    public static final String ACTION_START = "com.lcs.tproxy.START_ROOT";
    public static final String ACTION_STOP = "com.lcs.tproxy.STOP_ROOT";
    private long generation;
    private boolean expectedStop;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? "" : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            expectedStop = true;
            stopForeground(true);
            stopSelf();
            return START_NOT_STICKY;
        }
        generation = intent.getLongExtra(Control.EXTRA_GENERATION, 0);
        if (!Control.current(generation)) {
            stopSelf();
            return START_NOT_STICKY;
        }
        try {
            Notification n = Notify.build(this, "TinyProxy X", "热点模式正在连接", true);
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(Notify.ID, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(Notify.ID, n);
            }
        } catch (Throwable e) {
            Control.failStart(generation, "热点前台服务启动失败：" + e.getClass().getSimpleName());
            Control.stop(this);
            stopSelf();
            return START_NOT_STICKY;
        }
        new Thread(new Runnable() {
            public void run() {
                boot(generation);
            }
        }, "root-boot").start();
        return START_NOT_STICKY;
    }

    private void boot(long id) {
        if (!Control.current(id)) return;
        Store.Settings s = Store.I.settings;
        String err = Engine.I.start(this, true, id);
        if (err != null) {
            fail(id, err);
            return;
        }
        if (!Control.current(id)) return;
        List<String> ifs = Root.effectiveIfs(s);
        StringBuilder note = new StringBuilder();
        for (int i = 0; i < ifs.size(); i++) note.append(i > 0 ? "," : "").append(ifs.get(i));
        Profile p = Store.I.selected();
        String v6 = p == null ? Profile.V6_PROXY : p.v6;
        String script = Root.script(this, s, ifs, Engine.I.redirectPort, Engine.I.tproxyPort,
                android.os.Process.myUid(), v6, p);
        String r = Root.apply(this, script, id);
        if (r != null) {
            fail(id, "iptables 失败: " + r);
            return;
        }
        if (!Control.current(id)) {
            cleanupCancelledBoot();
            return;
        }
        armed(true);
        Engine.I.log("root 规则已核验：网卡 " + note
                + " · UDP " + policyText(p == null ? Profile.UDP_BLOCK : p.effectiveUdpPolicy())
                + " · QUIC443 " + policyText(p == null ? Profile.UDP_BLOCK : p.effectiveQuicPolicy())
                + " · DNS " + policyText(p == null ? Profile.DNS_PROXY : p.effectiveDnsPolicy())
                + " · IPv6 " + v6Text(v6));
        if (!Control.finishStart(id, p == null ? "" : p.name, true)) cleanupCancelledBoot();
    }

    private static String policyText(String p) {
        if (Profile.UDP_BLOCK.equals(p) || Profile.DNS_BLOCK.equals(p)) return "禁用";
        if (Profile.UDP_DIRECT.equals(p) || Profile.DNS_DIRECT.equals(p)) return "直连";
        return "代理";
    }

    private static String v6Text(String v6) {
        if (Profile.V6_BLOCK.equals(v6)) return "丢弃（DNS 按策略）";
        if (Profile.V6_DIRECT.equals(v6)) return "直连（会漏）";
        return "直送链路";
    }

    private void armed(boolean on) {
        Store.I.settings.rootArmed = on;
        Store.I.save();
    }

    private void fail(long id, String msg) {
        if (Control.failStart(id, msg)) {
            Engine.I.stopIfOwner(this, generation);
            boolean clean = Root.cleanup(this);
            armed(!clean);
            Control.message = msg + (clean ? "" : "；规则清理失败，已保留下次重试标记");
            Control.changed();
        }
        stopForeground(true);
        stopSelf();
    }

    private void cleanupCancelledBoot() {
        expectedStop = true;
        Engine.I.stopIfOwner(this, generation);
        if (Root.owns(generation)) armed(!Root.cleanupIfOwner(this, generation));
        stopForeground(true);
        stopSelf();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        expectedStop = true;
        Engine.I.log("任务卡片被移除，停止热点模式并清理规则");
        Control.stop(this);
        stopForeground(true);
        stopSelf();
        super.onTaskRemoved(rootIntent);
    }

    @Override
    public void onDestroy() {
        stopForeground(true);
        if (!expectedStop && !Control.busy() && !"idle".equals(Control.state) && Control.running()) Control.stop(this);
        super.onDestroy();
    }
}
