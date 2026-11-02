package com.lcs.tproxy.core;

import android.content.Context;

import com.lcs.tproxy.inject.Boot;
import com.lcs.tproxy.inject.HttpDns;
import com.lcs.tproxy.inject.Ini;
import com.lcs.tproxy.inject.InjectServer;
import com.lcs.tproxy.model.Node;
import com.lcs.tproxy.model.Profile;
import com.lcs.tproxy.model.Store;
import com.lcs.tproxy.xray.Conf;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/** Owns the native processes: xray, hev-socks5-tunnel,
 *  plus the in-process HTTP injector and its DNS resolver. */
public class Engine {

    public static final Engine I = new Engine();

    /** tun address handed to VpnService; tun2socks keeps the same identity */
    public static final String NETIF = "26.26.26.2";
    public static final String NETMASK = "255.255.255.0";

    public interface Listener {
        void onState(String state, String message);

        void onLog(String line);
    }

    private static class Proc {
        String name;
        Process p;
        boolean root;
    }

    private final List<Proc> procs = new ArrayList<Proc>();
    private final LinkedList<String> logs = new LinkedList<String>();
    private volatile long logVersion;
    private Listener listener;
    public volatile boolean running = false;
    public volatile String mode = "";
    public volatile String lastError = "";
    public volatile int socksPort = 10808;
    public volatile int httpPort = 10809;
    public volatile int tproxyPort = 12345;
    public volatile int redirectPort = 12346;
    private File configFile;
    private InjectServer injector;
    private final HttpDns dns = new HttpDns();
    /** 上一轮是不是 root 模式：决定收尾时要不要去清理 su 底下那群子进程 */
    private volatile boolean lastRoot = false;
    private volatile long ownerGeneration;

    public void setListener(Listener l) {
        listener = l;
    }

    /* ------------------------------------------------------------------ start */

    public synchronized String start(Context c, boolean root, long generation) {
        if (!Control.current(generation)) return "启动已取消";
        ownerGeneration = generation;
        boolean wasRoot = stopInner(c);
        /* 上一轮 root 跑过的话，xray 很可能还挂在 su 下面占着端口、占着 tproxy 端口。
         * 先扫干净再起，否则 bind 直接失败。 */
        if (root || wasRoot) {
            killStrays(c, android.os.Looper.myLooper() != android.os.Looper.getMainLooper());
        }
        lastError = "";
        Profile p = Store.I.selected();
        if (p == null || p.chain.isEmpty()) {
            lastError = "没有可用配置";
            emit("idle", lastError);
            return lastError;
        }
        /* 连接前再对一次账：用户可能刚改过列表里的 UDP 节点，而注入配置里的副本
         * 还是上一轮的。改过就写回存档，后续日志/编辑页看到的都是新配置。 */
        int synced = com.lcs.tproxy.model.NodeSync.reconcile();
        if (synced > 0) {
            Store.I.save();
            log("节点列表已更新：同步 " + synced + " 个 UDP 承载节点副本");
        }
        Store.Settings s = Store.I.settings;
        int[] ports = {s.socksPort, s.httpPort, s.tproxyPort, s.redirectPort};
        java.util.HashSet<Integer> used = new java.util.HashSet<Integer>();
        for (int port : ports) {
            if (port < 1 || port > 65535) return "端口必须在 1–65535：" + port;
            if (!used.add(port)) return "SOCKS/HTTP/TPROXY/REDIRECT 端口不能重复：" + port;
        }
        socksPort = s.socksPort;
        httpPort = s.httpPort;
        tproxyPort = s.tproxyPort;
        redirectPort = s.redirectPort;
        mode = root ? "root" : "vpn";
        try {
            if (Ports.localOpen(s.socksPort, false) || Ports.localOpen(s.httpPort, false))
                return "SOCKS/HTTP 端口已被其他进程占用，请换端口";
            prepareAssets(c);
            File xray = Bin.resolve(c, Bin.XRAY, root);
            if (xray == null || !xray.isFile()) {
                lastError = "缺少 xray 核心，请到设置里下载或导入";
                emit("idle", lastError);
                return lastError;
            }

            String chainErr = Conf.chainError(p);
            if (chainErr != null) throw new Exception(chainErr);
            /* 不致命但一定跑不顺的配置，先在日志里点名，别让人去猜满屏的失败 */
            String chainWarn = Conf.chainWarning(p);
            if (chainWarn != null) log("注意：" + chainWarn);

            /* 自定义 bootstrap：启动时把链路里的域名解析成 IP，结果留到断开连接。
             * 没开就保持原样（xray 自己解析）。 */
            Boot.begin(s);
            p = preResolve(p, s);

            int lead = Conf.leadCount(p);
            boolean inject = lead > 0 && Conf.leadIsInject(p);
            int injectPort = 0;

            if (inject) {
                /* HTTP 注入 / 免流：进程内实现，xray 用 http 出站接进来 */
                Ini ini = Ini.parse(p.chain.get(0).ini);
                dns.configure(ini, p.effectiveDnsPolicy());
                injector = new InjectServer(ini, dns, new InjectServer.LogSink() {
                    public void log(String line) {
                        Engine.this.log(line);
                    }
                });
                log("inject cfg: http=" + (ini.httpIp.length() > 0 ? ini.httpIp : "-")
                        + ":" + ini.httpPort + (ini.httpDispose && ini.httpFirst.length() > 0 ? "(注入)" : "(直连)")
                        + "  https=" + (ini.httpsIp.length() > 0 ? ini.httpsIp : "-")
                        + ":" + ini.httpsPort + (ini.httpsDispose && ini.httpsFirst.length() > 0 ? "(注入)" : "(直连)")
                        + "  dns=" + (ini.dnsUrl.length() > 0 ? ini.dnsUrl : ini.dnsIp)
                        + (ini.httpIp.length() == 0 && ini.httpsIp.length() == 0
                        ? "  ← 没有网关地址，这一跳只会原样转发" : ""));
                int want = ini.listenPort > 0 && ini.listenPort < 65536 ? ini.listenPort : 0;
                try {
                    injectPort = injector.start(want);
                } catch (Exception busy) {
                    injectPort = injector.start(0);
                }
                log("inject listening on 127.0.0.1:" + injectPort);
                Node udp = p.udpSplit();
                if (udp != null) {
                    log("udp 转换: " + udp.type.toUpperCase() + " " + udp.addr()
                            + (p.udpSplitViaInject()
                            ? "（服务器连接经注入网关）" : "（UDP 直连该节点）"));
                }
            }

            String cfg = Conf.build(p, s, root, injectPort).toString();
            String dnsNote = Conf.takeNotes();
            if (dnsNote != null) log("dns: " + dnsNote);
            configFile = new File(c.getFilesDir(), "config.json");
            FileOutputStream fos = new FileOutputStream(configFile);
            fos.write(pretty(cfg).getBytes("UTF-8"));
            fos.flush();
            fos.close();

            List<String> xa = new ArrayList<String>();
            xa.add(xray.getAbsolutePath());
            xa.add("run");
            xa.add("-c");
            xa.add(configFile.getAbsolutePath());
            Map<String, String> env = new HashMap<String, String>();
            env.put("XRAY_LOCATION_ASSET", assetDir(c).getAbsolutePath());
            if (!spawn(c, xa, "xray", root, env)) {
                lastError = (root ? "xray 启动失败（root 通道不可用）：" : "xray 启动失败：")
                        + tailLog(6);
                emit("idle", lastError);
                return lastError;
            }
            /* A sleep is not readiness: require the child alive and every public listener bound. */
            long deadline = System.currentTimeMillis() + 4000;
            while (System.currentTimeMillis() < deadline && aliveByName("xray")
                    && (!Ports.localOpen(s.socksPort, false) || !Ports.localOpen(s.httpPort, false))) {
                Thread.sleep(100);
            }
            if (!Control.current(generation)) {
                stopIfOwner(c, generation);
                return "启动已取消";
            }
            if (!aliveByName("xray")) throw new Exception("xray 配置加载失败：" + tailLog(6));
            if (!Ports.localOpen(s.socksPort, false) || !Ports.localOpen(s.httpPort, false))
                throw new Exception("xray 本地监听未就绪，请检查端口占用：" + tailLog(4));
            running = true;
            emit("running", root ? "ROOT 模式运行中" : "VPN 模式运行中");
            selfCheck(s.socksPort, root);
            return null;
        } catch (Exception e) {
            lastError = e.getMessage() == null ? e.toString() : e.getMessage();
            stopIfOwner(c, generation);
            emit("idle", lastError);
            return lastError;
        }
    }

    /* ------------------------------------------------------------------ tun2socks */

    /** tun2socks is now hev-socks5-tunnel, called in-process: the VpnService fd is handed to
     *  native code directly, so there is no exec, no inherited fd and no unix-socket dance. */
    public synchronized String startTun(Context c, android.os.ParcelFileDescriptor tun, int fd,
                                        boolean root) {
        File cfg = new File(c.getFilesDir(), "hev.yaml");
        File logf = new File(c.getFilesDir(), "hev.log");
        String yaml = "tunnel:\n"
                + "  mtu: 1500\n"
                + "socks5:\n"
                + "  port: " + socksPort + "\n"
                + "  address: 127.0.0.1\n"
                + "  udp: 'udp'\n"
                + "misc:\n"
                + "  log-file: " + logf.getAbsolutePath() + "\n"
                + "  log-level: warn\n"
                + "  task-stack-size: 20480\n";
        try {
            FileOutputStream fos = new FileOutputStream(cfg);
            fos.write(yaml.getBytes("UTF-8"));
            fos.flush();
            fos.close();
        } catch (Exception e) {
            return "写 hev 配置失败：" + e.getMessage();
        }
        try {
            if (logf.exists()) logf.delete();
            Class<?> k = Class.forName("hev.htproxy.TProxyService");
            Object r = k.getMethod("TProxyStartService", String.class, int.class)
                    .invoke(null, cfg.getAbsolutePath(), fd);
            boolean ok = r instanceof Boolean && ((Boolean) r).booleanValue();
            if (!ok) {
                try {
                    k.getMethod("TProxyStopService").invoke(null);
                } catch (Exception ignored) {
                }
                return "hev-socks5-tunnel 启动失败：" + tailFile(logf, 6);
            }
            log("hev-socks5-tunnel started: socks 127.0.0.1:" + socksPort + " mtu 1500");
            return null;
        } catch (Throwable e) {
            return "hev-socks5-tunnel 不可用：" + e.getClass().getSimpleName()
                    + " " + (e.getMessage() == null ? "" : e.getMessage());
        }
    }

    /** stop the in-process tunnel; safe to call when it never started */
    public void stopTun() {
        try {
            Class<?> k = Class.forName("hev.htproxy.TProxyService");
            k.getMethod("TProxyStopService").invoke(null);
        } catch (Throwable ignored) {
        }
    }

    private static String tailFile(File f, int lines) {
        try {
            if (!f.exists()) return "无日志";
            List<String> l = Bin.readLines(f);
            StringBuilder b = new StringBuilder();
            int from = Math.max(0, l.size() - lines);
            for (int i = from; i < l.size(); i++) b.append(i > from ? " | " : "").append(l.get(i));
            return b.length() == 0 ? "无日志" : b.toString();
        } catch (Exception e) {
            return "读日志失败";
        }
    }

    /* ------------------------------------------------------------------ lifecycle */

    public synchronized void stop(Context c) {
        ownerGeneration = 0;
        if (stopInner(c)) killStrays(c, true);
    }

    /** Obsolete workers may clean only their own generation, never a newer Engine instance. */
    public synchronized void stopIfOwner(Context c, long generation) {
        if (generation == 0 || ownerGeneration != generation) return;
        ownerGeneration = 0;
        if (stopInner(c)) killStrays(c, true);
    }

    /** 只打断自己手里的进程句柄；su 起的那群由 {@link #killStrays} 负责 */
    private boolean stopInner(Context c) {
        boolean wasRoot = lastRoot;
        for (Proc p : new ArrayList<Proc>(procs)) {
            try {
                if (p.p != null) p.p.destroy();
            } catch (Exception ignored) {
            }
        }
        if (injector != null) {
            injector.stop();
            injector = null;
        }
        dns.stop();
        Boot.clear();
        procs.clear();
        running = false;
        lastRoot = false;
        emit("idle", "已停止");
        return wasRoot;
    }

    /**
     * root 模式下 xray 是 <code>su -c</code> 的子进程：destroy 掉 su 不会带走它，
     * 端口就一直被占着，下次启动 bind 失败 —— 这就是「停止后 xray/sh 还在、端口不释放」。
     * 这里按 /proc/&lt;pid&gt;/cmdline 精确匹配，只清理我们自己起的那几个。
     */
    private void killStrays(Context c, boolean blocking) {
        final File cfg = configFile != null ? configFile : new File(c.getFilesDir(), "config.json");
        StringBuilder sb = new StringBuilder();
        sb.append("#!/system/bin/sh\nset +e\n");
        sb.append("CFG='").append(cfg.getAbsolutePath()).append("'\n");
        sb.append("for p in /proc/[0-9]*; do\n");
        sb.append("  pid=${p#/proc/}\n");
        sb.append("  [ \"$pid\" = \"$$\" ] && continue\n");
        sb.append("  cmd=$(tr '\\0' ' ' < $p/cmdline 2>/dev/null)\n");
        sb.append("  case \"$cmd\" in\n");
        sb.append("    *\"$CFG\"*) kill -9 $pid 2>/dev/null; continue ;;\n");
        sb.append("  esac\n");
        /* tr 在个别 ROM 上不给力时兜底：只认带本包路径的 libxray，
         * 别把用户另一个代理 App 的 core 一起杀了 */
        sb.append("  case \"$cmd\" in\n");
        sb.append("    *com.lcs.tproxy*)\n");
        sb.append("      case \"$cmd\" in\n");
        sb.append("        *libxray.so*) kill -9 $pid 2>/dev/null ;;\n");
        sb.append("      esac ;;\n");
        sb.append("  esac\n");
        sb.append("done\n");
        sb.append("echo STRAYS_CLEARED\n");
        final File f = new File(c.getFilesDir(), "kill.sh");
        try {
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(sb.toString().getBytes("UTF-8"));
            fos.flush();
            fos.close();
        } catch (Exception e) {
            return;
        }
        Runnable r = new Runnable() {
            public void run() {
                Bin.runAndRead(6000L, "su", "-c", "sh " + f.getAbsolutePath());
            }
        };
        if (blocking) {
            r.run();
            return;
        }
        Thread t = new Thread(r, "kill-strays");
        t.setDaemon(true);
        t.start();
    }

    /** 给 Control.sweepStaleRoot 用：崩过之后兜底清进程 */
    public void killRootStrays(Context c) {
        killStrays(c, false);
    }

    /* ------------------------------------------------------------ self check */

    /** 启动自检：直接从本机连一次节点地址。通了说明网络没问题；不通会带上内核原话
     *  （network is unreachable / refused），一眼能分出是节点、网络还是规则的事。 */
    private void selfCheck(final int socksPort, final boolean root) {
        Profile p = Store.I.selected();
        if (p == null || p.chain.isEmpty()) return;
        Node exit = p.chain.get(p.chain.size() - 1);
        final String host = exit.host;
        final int port = exit.port;
        if (host == null || host.length() == 0 || port <= 0) return;
        Thread t = new Thread(new Runnable() {
            public void run() {
                long t0 = System.currentTimeMillis();
                java.net.Socket s = null;
                String r;
                try {
                    s = new java.net.Socket();
                    s.connect(new java.net.InetSocketAddress(host, port), 4000);
                    r = "通（" + (System.currentTimeMillis() - t0) + " ms）";
                } catch (Exception e) {
                    r = "不通：" + (e.getMessage() == null ? e.toString() : e.getMessage())
                            + "（" + (System.currentTimeMillis() - t0) + " ms）";
                } finally {
                    try {
                        if (s != null) s.close();
                    } catch (Exception ignored) {
                    }
                }
                log("自检：节点 " + host + ":" + port + " → " + r);
                if (root) {
                    log("自检：v4 默认路由 " + routeLine("ip route show default"));
                    log("自检：v6 默认路由 " + routeLine("ip -6 route show default"));
                }
            }
        }, "self-check");
        t.setDaemon(true);
        t.start();
    }

    private static String routeLine(String cmd) {
        String out = Bin.runAndRead("su", "-c", cmd + " 2>&1 | head -n2");
        if (out == null) return "取不到";
        out = out.trim();
        return out.length() == 0 ? "无" : out.replace('\n', ' ');
    }

    /* ------------------------------------------------------------ bootstrap */

    /** bootstrap 开启时，把链路里的域名换成 IP：xray 不用再解析自己的服务器地址。
     *  SNI 留原域名，证书校验照常。解析失败直接报错，不回退系统 DNS。 */
    private Profile preResolve(Profile p, Store.Settings s) {
        if (!Boot.enabled()) return p;
        if (p.rawJson != null && p.rawJson.length() > 0) {
            log("bootstrap: 完整 JSON 配置里的域名不经过 bootstrap");
            return p;
        }
        Profile run = p.copy();
        /* 注入链路：后面几跳是被注入器用 CONNECT 带出去的，域名必须原样交给网关
         * （免流网关按域名放行）。钉成 IP 的话网关认不出来，握手后直接断。 */
        if (Conf.leadIsInject(p)) {
            log("bootstrap: 注入链路，后续节点保留域名（网关按域名放行）");
            return run;
        }
        int hits = 0;
        for (Node n : run.chain) {
            if (n.host == null || n.host.length() == 0) continue;
            if (Node.INJECT.equals(n.type) || isIp(n.host)) continue;
            String ip = Boot.resolve(n.host);
            if (ip == null) {
                /* 钉不上就按原样继续：xray 自己还会用系统解析试一次，
                 * 一票否决只会让人连"哪一步失败"都看不到。 */
                log("bootstrap: " + n.host + " 解析失败，保留域名交给 xray 自己解析");
                continue;
            }
            if (n.sni == null || n.sni.length() == 0) n.sni = n.host;
            log("bootstrap: " + n.host + " → " + ip);
            n.host = ip;
            hits++;
        }
        log("bootstrap: " + Boot.describe() + "，本次解析 " + hits + " 个节点域名，缓存到断开");
        return run;
    }

    /** 与注入器共用同一套字面量判定，别再维护第二份。 */
    private static boolean isIp(String h) {
        return HttpDns.isIp(h);
    }

    /** null when the injector is fine; otherwise a one-line reason for the UI */
    public String injectStatus() {
        if (injector == null || injector.failCount == 0) return null;
        return "注入失败 " + injector.failCount + " 次：" + injector.lastFailLine;
    }

    public boolean isRunning() {
        return running && aliveByName("xray");
    }

    private boolean aliveByName(String name) {
        for (Proc p : procs) {
            if (name.equals(p.name) && p.p != null && p.p.isAlive()) return true;
        }
        return false;
    }

    /* ------------------------------------------------------------------ process */

    private boolean spawn(Context c, List<String> args, String name, boolean root,
                          Map<String, String> env) {
        try {
            ProcessBuilder pb;
            if (root) {
                StringBuilder cmd = new StringBuilder();
                if (env != null) {
                    for (Map.Entry<String, String> e : env.entrySet()) {
                        cmd.append("export ").append(e.getKey()).append("=")
                                .append(sq(e.getValue())).append("; ");
                    }
                }
                cmd.append("export TZ=")
                        .append(sq(java.util.TimeZone.getDefault().getID())).append("; ");
                for (String a : args) cmd.append(sq(a)).append(" ");
                pb = new ProcessBuilder("su", "-c", cmd.toString());
            } else {
                pb = new ProcessBuilder(args);
                if (env != null) pb.environment().putAll(env);
                /* child processes inherit a bare env: without TZ every xray line is UTC */
                pb.environment().put("TZ", java.util.TimeZone.getDefault().getID());
            }
            pb.redirectErrorStream(true);
            final Proc pr = new Proc();
            pr.name = name;
            pr.root = root;
            if (root) lastRoot = true;
            pr.p = pb.start();
            procs.add(pr);
            final String tag = name;
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        InputStream in = pr.p.getInputStream();
                        byte[] b = new byte[2048];
                        int n;
                        while ((n = in.read(b)) > 0) {
                            String s = new String(b, 0, n, "UTF-8");
                            for (String line : s.split("[\\r\\n]+")) {
                                if (line.trim().length() > 0) log(tag + ": " + line.trim());
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            });
            t.setDaemon(true);
            t.start();
            Thread.sleep(120);
            if (!pr.p.isAlive() && !root) {
                log(tag + ": 启动即退出 (exit=" + safeExit(pr.p) + ")");
                procs.remove(pr);
                return false;
            }
            return true;
        } catch (Exception e) {
            log(name + ": " + e.getMessage());
            return false;
        }
    }

    private static int safeExit(Process p) {
        try {
            return p.exitValue();
        } catch (Exception e) {
            return -1;
        }
    }

    private static String sq(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    /* ------------------------------------------------------------------ assets */

    public File assetDir(Context c) {
        File d = new File(c.getFilesDir(), "assets");
        if (!d.exists()) d.mkdirs();
        return d;
    }

    /** geoip/geosite/mmdb must sit next to xray or under XRAY_LOCATION_ASSET. */
    public void prepareAssets(Context c) {
        File d = assetDir(c);
        String[] names = {"geoip.dat", "geosite.dat", "Country.mmdb"};
        for (String n : names) {
            File f = new File(d, n);
            if (f.exists() && f.length() > 1000) continue;
            try {
                InputStream in = c.getAssets().open(n);
                OutputStream out = new FileOutputStream(f);
                byte[] b = new byte[1 << 16];
                int k;
                while ((k = in.read(b)) > 0) out.write(b, 0, k);
                out.flush();
                out.close();
                in.close();
            } catch (Exception ignored) {
            }
        }
        for (String n : names) {
            File src = new File(d, n);
            File dst = new File(c.getFilesDir(), n);
            if (src.exists() && (!dst.exists() || dst.length() != src.length())) {
                try {
                    java.io.FileInputStream in = new java.io.FileInputStream(src);
                    OutputStream out = new FileOutputStream(dst);
                    byte[] b = new byte[1 << 16];
                    int k;
                    while ((k = in.read(b)) > 0) out.write(b, 0, k);
                    out.close();
                    in.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /* ------------------------------------------------------------------ logs */

    private static String pretty(String json) {
        try {
            return new JSONObject(json).toString(2);
        } catch (Exception e) {
            return json;
        }
    }

    public void log(String line) {
        String stamp = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
                .format(new java.util.Date());
        int cap = Math.max(100, Store.I.settings.logLines);
        synchronized (logs) {
            logs.add(stamp + "  " + line);
            while (logs.size() > cap) logs.removeFirst();
            logVersion++;
        }
        if (listener != null) listener.onLog(line);
    }

    private void emit(String state, String msg) {
        if (listener != null) listener.onState(state, msg);
    }

    /** last few log lines, used to explain a failed child process */
    public String tailLog(int n) {
        StringBuilder b = new StringBuilder();
        synchronized (logs) {
            int from = Math.max(0, logs.size() - n);
            for (int i = from; i < logs.size(); i++) {
                b.append(i > from ? " | " : "").append(logs.get(i));
            }
        }
        return b.length() == 0 ? "无输出" : b.toString();
    }

    public void clearLog() {
        synchronized (logs) {
            logs.clear();
            logVersion++;
        }
    }

    /** Monotonic change counter; safe even when the newest line happens to repeat. */
    public long logVersion() {
        return logVersion;
    }

    /** newest first */
    public java.util.List<String> logLines() {
        java.util.ArrayList<String> out = new java.util.ArrayList<String>();
        synchronized (logs) {
            for (int i = logs.size() - 1; i >= 0; i--) out.add(logs.get(i));
        }
        return out;
    }

    public String logText() {
        StringBuilder sb = new StringBuilder();
        synchronized (logs) {
            for (String l : logs) sb.append(l).append('\n');
        }
        return sb.toString();
    }

    public String configText() {
        if (configFile == null || !configFile.exists()) return "";
        List<String> l = Bin.readLines(configFile);
        StringBuilder sb = new StringBuilder();
        for (String s : l) sb.append(s).append('\n');
        return sb.toString();
    }
}
