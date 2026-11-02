package com.lcs.tproxy.inject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** The 3.2.7 injector (免流), rebuilt from the package's own bytecode.
 *
 *  Authoritative behaviour, taken from ProxyTask.sock5_check / ProxyTask.doConnect /
 *  SocketThreadOutput.httpmod:
 *   - the endpoint is chosen by destination port: port 80 uses http_ip:http_port and the request
 *     itself is rewritten, every other port uses https_ip:https_port with a CONNECT handshake.
 *   - CONNECT template placeholders: [H]/[host] expand to "host:port" (NOT the bare host),
 *     [M]/[method] to CONNECT, [V]/[version] to HTTP/1.1.
 *   - HTTP template placeholders: [M] to the method, [H] to the Host header value,
 *     [U]/[uri] to the raw request target, [V] to the version.
 *   - the http template replaces the client's whole header block; only the body survives.
 *   - every template is terminated by exactly one blank line.
 *   - with no template the CONNECT line carries Host and User-Agent.
 *
 *  One structural difference: xray's http outbound always opens a CONNECT tunnel, even for
 *  port 80 (verified against Xray 26.10.21), where the original's SOCKS front end handed over a
 *  bare request. So for the http slot we answer the tunnel first and then rewrite the first
 *  request that arrives inside it — same bytes reach the gateway as in the original.
 *
 *  <p>热路径改造：请求头只扫一遍（不再 split 出数组）、模板单趟替换（不再 8 次 replace）、
 *  状态机换成 256 项转移表、三种去向用路径表分派、握手顺序用三维表取，
 *  最大尝试次数固定为 2，直接展开。 */
public class InjectServer {

    public interface LogSink {
        void log(String line);
    }

    /** LocalVpnService.userAgent in 3.2.7: the default CONNECT advertises a desktop Chrome. */
    public static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            + " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    /** 0 = CONNECT, 1..7 = other known methods, -1 = unknown. */
    private static final int M_CONNECT = 0;

    /* ------------------------------------------------------------ request parsing */

    /** One parsed request head. */
    static final class Req {
        String method = "GET";
        String target = "";
        String version = "HTTP/1.1";
        String hostHeader = "";
        String host = "";
        int port = 80;

        static Req of(String text) {
            Req r = new Req();
            int end = text.indexOf("\r\n");
            if (end < 0) end = text.length();
            /* 原实现是 lines[0].split(" ")：按单个空格切，空串也算一段。
             * 这里用三个下标复刻同一套语义（连续空格 → 中间那段是空串），不建数组。 */
            int s1 = space(text, 0, end);
            int s2 = s1 < 0 ? -1 : space(text, s1 + 1, end);
            int s3 = s2 < 0 ? -1 : space(text, s2 + 1, end);
            /* Java 的 split(" ") 会丢掉尾部空段：整行只有空格时连第一段都没有；
             * 行尾那个空格后面也不会多出一个空版本号。这两处按原语义补齐。 */
            if (s1 == 0 && end > 0 && blank(text, 0, end)) {
                r.method = "GET";
            } else {
                r.method = text.substring(0, s1 < 0 ? end : s1).toUpperCase(Locale.ROOT);
            }
            if (s1 >= 0) r.target = text.substring(s1 + 1, s2 < 0 ? end : s2);
            /* 版本段存在 ⟺ 它后面还有非空格字符；否则 split 会把它当尾部空段丢掉。 */
            if (s2 >= 0 && !blank(text, s2 + 1, end)) {
                r.version = text.substring(s2 + 1, s3 < 0 ? end : s3);
            }
            r.hostHeader = headerValue(text, end, "host");
            r.host = hostOf(r.target, r.hostHeader);
            r.port = portOf(r.target, methodId(r.method) == M_CONNECT ? 1 : 0);
            return r;
        }
        boolean tunnel() {
            return methodId(method) == M_CONNECT;
        }
    }

    /* ------------------------------------------------------------ method ids */

    /** 8 个方法名，下标即协议里用的 id。 */
    private static final String[] METHODS = {
            "CONNECT", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};

    /** (长度 << 5) | (首字符 & 31) → 1+id，0 = 不是已知方法。ASCII 方法名长度 3..7，表 8×32。 */
    private static final int[] MID = new int[8 << 5];

    static {
        for (int i = 0; i < METHODS.length; i++) {
            String s = METHODS[i];
            MID[(s.length() << 5) | (s.charAt(0) & 31)] = i + 1;
        }
    }

    /** 一次数组访存定位候选，只有命中才比对整串：没有 switch 分派树，也没有 8 次 equals。 */
    static int methodId(String m) {
        int n = m == null ? 0 : m.length();
        int id = n < 3 || n > 7 ? 0 : MID[(n << 5) | (m.charAt(0) & 31)];
        return id != 0 && METHODS[id - 1].equals(m) ? id - 1 : -1;
    }

    private final Ini conf;
    private final HttpDns dns;
    private final LogSink sink;
    /** http_del 解析一次，之后每条请求只做长度+逐字符比较，不再 split/lowercase。 */
    private final String[] httpDrop;
    private ServerSocket socket;
    public volatile int port;
    public volatile boolean running;
    public volatile String lastError = "";
    /** 0 = unknown, 1 = template worked, 2 = plain CONNECT worked */
    private volatile int strategy = 0;
    private volatile String lastHandshake = "";
    public volatile int failCount = 0;
    public volatile String lastFailLine = "";
    /* 某个握手方式刚被拒过就先跳过 30 秒，避免每条连接都白试两次 */
    private volatile long tplFailAt = 0;
    private volatile long plainFailAt = 0;
    /* 同一个目标失败会被客户端反复重试（一个死节点能刷几百行一样的日志）。
     * 记录最近一次结果的时间，一分钟内只放第一条和每 25 次一条，其余折叠。 */
    private final Map<String, long[]> rep = new LinkedHashMap<String, long[]>() {
        protected boolean removeEldestEntry(Map.Entry<String, long[]> e) {
            return size() > 64;
        }
    };

    /* 目标级熔断：同一个目标连续失败 FAIL_LIMIT 次就冷却 COOLDOWN_MS。
     * 实测（链路握手失败.log）：链路里下一跳的地址被免流网关拒了以后，xray 每条连接都要
     * 再敲一次网关，19 秒里敲了 175 次、累计 600+ 次 —— 日志被刷爆，还可能把网关惹到限速，
     * 连带把正常的图/直播也拖垮。冷却期内直接本地拒绝，不再发 CONNECT。 */
    private static final int FAIL_LIMIT = 8;
    private static final long COOLDOWN_MS = 30000L;
    private final Map<String, long[]> brk = new LinkedHashMap<String, long[]>() {
        protected boolean removeEldestEntry(Map.Entry<String, long[]> e) {
            return size() > 128;
        }
    };
    /* 网关对 IPv6 目标明确拒绝过两次以上：之后 v6 目标本地直接跳过，不再问网关 */
    private volatile boolean gwNoV6 = false;
    private volatile int v6Fails = 0;

    /** true = 现在可以去试这个目标 */
    private synchronized boolean allow(String target) {
        long[] v = brk.get(target);
        return v == null || v[1] <= System.currentTimeMillis();
    }

    private synchronized void markFail(String target, String host) {
        long[] v = brk.get(target);
        if (v == null) v = new long[]{0, 0};
        v[0]++;
        v[1] = v[0] >= FAIL_LIMIT ? System.currentTimeMillis() + COOLDOWN_MS : 0;
        if (v[0] >= FAIL_LIMIT) v[0] = 0;
        brk.put(target, v);
        if (host.indexOf(':') >= 0 && ++v6Fails >= 2) gwNoV6 = true;
    }

    private synchronized void markOk(String target) {
        brk.remove(target);
        v6Fails = 0;
    }

    /** true = 这一行值得打；false = 一分钟内的重复。 */
    private synchronized boolean note(String key) {
        long now = System.currentTimeMillis();
        long[] v = rep.get(key);
        if (v == null || now - v[1] > 60000L) {
            rep.put(key, new long[]{1, now});
            return true;
        }
        v[0]++;
        v[1] = now;
        return v[0] % 25 == 0;
    }

    private synchronized int hits(String key) {
        long[] v = rep.get(key);
        return v == null ? 1 : (int) v[0];
    }

    public InjectServer(Ini conf, HttpDns dns) {
        this(conf, dns, null);
    }

    public InjectServer(Ini conf, HttpDns dns, LogSink sink) {
        this.conf = conf;
        this.dns = dns;
        this.sink = sink;
        this.httpDrop = splitDrop(conf.httpDel);
    }

    /** 逗号/分号分隔的头名，统一小写去空白；只做一次。 */
    private static String[] splitDrop(String s) {
        if (s == null || s.length() == 0) return new String[0];
        ArrayList<String> out = new ArrayList<String>(4);
        int start = 0;
        for (int i = 0; i <= s.length(); i++) {
            boolean cut = i == s.length() || s.charAt(i) == ',' || s.charAt(i) == ';';
            if (!cut) continue;
            String v = s.substring(start, i).trim();
            if (v.length() > 0) out.add(v.toLowerCase(Locale.ROOT));
            start = i + 1;
        }
        return out.toArray(new String[0]);
    }

    private void log(String line) {
        if (sink != null) sink.log(line);
    }

    /* 每条连接 new Thread 的代价：一次 pthread 创建 + 一份线程栈（默认 1MB 虚拟地址、
     * 实际提交几十 KB），连接断开就全扔掉，短连接场景下创建/销毁比真正干活还贵。
     * 改成有界池：空闲线程 30 秒回收，线程名固定前缀便于看栈；池满时直接拒绝新连接，
     * 而不是把线程数堆到 OOM。 */
    /* 一条隧道占两个线程（上行处理 + 下行泵），所以线程上限按隧道的两倍留：
     * 512 个线程 = 256 条并发隧道，手机上的浏览器/图床并发远到不了这个量级。 */
    private static final int MAX_WORKERS = 512;
    private java.util.concurrent.ThreadPoolExecutor pool;

    private java.util.concurrent.ThreadPoolExecutor newPool() {
        return new java.util.concurrent.ThreadPoolExecutor(0, MAX_WORKERS, 30L,
                java.util.concurrent.TimeUnit.SECONDS,
                new java.util.concurrent.SynchronousQueue<Runnable>(),
                new java.util.concurrent.ThreadFactory() {
                    private final java.util.concurrent.atomic.AtomicInteger seq =
                            new java.util.concurrent.atomic.AtomicInteger();

                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "inj-" + seq.incrementAndGet());
                        t.setDaemon(true);
                        return t;
                    }
                });
    }

    /** @return false = 池已满/已关闭，调用方负责收摊 */
    private boolean submit(Runnable r) {
        java.util.concurrent.ThreadPoolExecutor p = pool;
        if (p == null) return false;
        try {
            p.execute(r);
            return true;
        } catch (java.util.concurrent.RejectedExecutionException e) {
            return false;
        }
    }

    public int start(int preferred) throws IOException {
        ServerSocket s = new ServerSocket();
        s.setReuseAddress(true);
        s.bind(new InetSocketAddress("127.0.0.1", preferred > 0 ? preferred : 0), 128);
        socket = s;
        port = s.getLocalPort();
        pool = newPool();
        running = true;
        Thread t = new Thread(new Runnable() {
            public void run() {
                acceptLoop();
            }
        }, "inject-accept");
        t.setDaemon(true);
        t.start();
        return port;
    }

    public void stop() {
        running = false;
        try {
            if (socket != null) socket.close();
        } catch (Exception ignored) {
        }
        socket = null;
        java.util.concurrent.ThreadPoolExecutor p = pool;
        pool = null;
        if (p != null) p.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                final Socket c = socket.accept();
                if (submit(new Runnable() {
                    public void run() {
                        handle(c);
                    }
                })) continue;
                lastError = "注入器并发连接已满（" + MAX_WORKERS + "），拒绝新连接";
                close(c);
            } catch (Exception e) {
                if (!running) return;
                lastError = e.getMessage() == null ? e.toString() : e.getMessage();
            }
        }
    }

    /* ------------------------------------------------------------------ path */

    /**
     * 三种去向，查表分派：
     * <pre>
     *   0 直连目标（没有网关，或 _direct=on）
     *   1 经网关 CONNECT（443 槽，或 80 被 https 槽接管）
     *   2 http 槽：先连网关（或目标）再逐条改写请求头
     * </pre>
     * 下标 = slot(2) × use(2) × gw(2)。
     */
    private static final int[][][] PATH = new int[2][2][2];

    /** [slot][httpOn][httpDirect][httpIpEmpty] → 用哪个槽 */
    private static final int[][][][] USE = new int[2][2][2][2];

    /** [use][on][direct][empty] → 这一槽有没有可用网关 */
    private static final boolean[][][][] GW = new boolean[2][2][2][2];

    /** [strategy][tplOk][plainOk] → 这次握手尝试的顺序 */
    private static final int[][][][] ORDER = new int[3][2][2][];

    /** 头结束状态机：state*256 + byte → next state，4 = 收到完整头。 */
    private static final byte[] HEAD = new byte[5 * 256];

    static {
        /* 2.0.1 的写法是把三张表塞进同一个四重循环里顺手写：循环变量是 **http 槽**的
         * on/direct/empty，可 PATH 的第三维 gw 取的是 **目标槽** 的网关状态。端口 80
         * 交给 https 槽时目标槽是 https，而 (slot=0, use=1, gw=1) 这一格只有
         * 「http 槽本身有网关」才会被写到——那又恰好不是接管的情况。于是
         * PATH[0][1][1] 一直是 0（直连）：
         *   http_ip 空、https_ip 有值 → 80 端口进了 directTunnel：
         *   给 xray 回 200，然后把明文请求原样倒进免流网关的 443 端口，
         *   没有 CONNECT、没有模板，网关直接不认 —— 直播间、网页全打不开。
         * 三张表现在各自整表填满，取值和 1.8.2 的 sock5_check 逐格对齐。 */
        for (int slot = 0; slot < 2; slot++) {
            for (int on = 0; on < 2; on++) {
                for (int direct = 0; direct < 2; direct++) {
                    for (int empty = 0; empty < 2; empty++) {
                        USE[slot][on][direct][empty] =
                                slot == 0 && on == 1 && direct == 0 && empty == 1 ? 1 : slot;
                    }
                }
            }
        }
        /* 网关只看「实际要用的那一槽」自己的三个开关（on / !direct / ip 非空）。 */
        for (int use = 0; use < 2; use++) {
            for (int on = 0; on < 2; on++) {
                for (int direct = 0; direct < 2; direct++) {
                    for (int empty = 0; empty < 2; empty++) {
                        GW[use][on][direct][empty] = on == 1 && direct == 0 && empty == 0;
                    }
                }
            }
        }
        for (int slot = 0; slot < 2; slot++) {
            for (int use = 0; use < 2; use++) {
                for (int gw = 0; gw < 2; gw++) {
                    /* 没网关：两边都直连，一个字节都不改（http_first 也不能注入）；
                     * 有网关：https 槽发 CONNECT，http 槽逐条改写请求头。 */
                    PATH[slot][use][gw] = gw == 0 ? 0 : use == 1 ? 1 : 2;
                }
            }
        }
        int[] one = {1};
        int[] two = {2};
        int[] both = {1, 2};
        for (int st = 0; st < 3; st++) {
            for (int tpl = 0; tpl < 2; tpl++) {
                for (int plain = 0; plain < 2; plain++) {
                    boolean t = tpl == 1;
                    boolean p = plain == 1;
                    ORDER[st][tpl][plain] = st == 1 && t ? one
                            : st == 2 && p ? two
                            : !t && p ? two
                            : t && !p ? one : both;
                }
            }
        }
        for (int s = 0; s < 5; s++) {
            for (int b = 0; b < 256; b++) {
                int next;
                if (b == '\r' && (s == 0 || s == 2)) next = s + 1;
                else if (b == '\n' && (s == 1 || s == 3)) next = s + 1;
                else next = 0;
                HEAD[(s << 8) | b] = (byte) next;
            }
        }
    }

    /**
     * 请求侧/网关侧的带缓冲输入：块读一次读一大段，头或行结束后多读的字节原地留在
     * {@code buf[pos..len)} 里，后面的隧道转发、下一条请求都从这里接着消费。
     *
     * <p>不用 {@code PushbackInputStream}：它的 unread 缓冲区与"每次只读 512 字节"的循环
     * 叠在一起时，回退过的字节会被下一次 fill 覆盖，实测表现为早期数据（TLS ClientHello）
     * 偶发丢失、连接卡到超时。自己持有缓冲没有这个歧义，也少一次内存拷贝。
     */
    private static final class BufIn extends InputStream {
        private final InputStream in;
        private byte[] buf = new byte[2048];
        private int len;
        private int pos;

        BufIn(InputStream in) {
            this.in = in;
        }

        /** 丢弃 pos 之前的字节，把剩余数据挪到开头。 */
        private void compact() {
            if (pos == 0) return;
            if (pos < len) System.arraycopy(buf, pos, buf, 0, len - pos);
            len -= pos;
            pos = 0;
        }

        /** @return 本次读到的字节数；<=0 表示 EOF 或已达上限 */
        private int fill(int cap) throws IOException {
            if (len == buf.length) {
                if (buf.length >= cap) return -1;
                buf = java.util.Arrays.copyOf(buf, Math.min(cap, buf.length << 1));
            }
            int r = in.read(buf, len, buf.length - len);
            if (r > 0) len += r;
            return r;
        }

        /** 读一个完整请求头（到 CRLFCRLF）；多读的字节留在缓冲里。EOF 返回 null。 */
        byte[] head() throws IOException {
            compact();
            int st = 0;
            int scan = 0;
            while (len < 16384) {
                for (int i = scan; i < len; i++) {
                    st = HEAD[(st << 8) | (buf[i] & 0xff)];
                    if (st != 4) continue;
                    byte[] h = java.util.Arrays.copyOf(buf, i + 1);
                    pos = i + 1;
                    return h;
                }
                scan = len;
                if (fill(16384) <= 0) break;
            }
            if (len == 0) return null;
            byte[] h = java.util.Arrays.copyOf(buf, len);
            pos = len;
            return h;
        }

        /** 读一行（含 \n）；多读的字节留在缓冲里。EOF 返回 null。 */
        String line() throws IOException {
            compact();
            int scan = 0;
            while (len < 8192) {
                for (int i = scan; i < len; i++) {
                    if (buf[i] != '\n') continue;
                    String s = new String(buf, 0, i + 1, StandardCharsets.ISO_8859_1);
                    pos = i + 1;
                    return s;
                }
                scan = len;
                if (fill(8192) <= 0) break;
            }
            if (len == 0) return null;
            String s = new String(buf, 0, len, StandardCharsets.ISO_8859_1);
            pos = len;
            return s;
        }

        /** 只回退刚读出来的那一个字节（swallowBlank 用）。 */
        void unread(int b) {
            if (b < 0) return;                       /* EOF 没有字节可回退 */
            if (pos == 0) {
                /* 正常路径不会走到这里（刚 read 成功，pos 至少为 1）。留在缓冲里的数据
                 * 前面已经没有空位，整体右移一格腾位置，宁可多一次拷贝也不丢字节。 */
                if (len == buf.length) buf = java.util.Arrays.copyOf(buf, len + 1);
                System.arraycopy(buf, 0, buf, 1, len);
                len++;
                pos = 1;
            }
            buf[--pos] = (byte) b;
        }

        public int read() throws IOException {
            if (pos >= len) {
                compact();
                if (fill(16384) <= 0) return -1;
            }
            return buf[pos++] & 0xff;
        }

        public int read(byte[] b, int off, int l) throws IOException {
            if (l == 0) return 0;
            if (pos >= len) {
                compact();
                if (l >= buf.length) return in.read(b, off, l);
                if (fill(16384) <= 0) return -1;
            }
            int n = Math.min(l, len - pos);
            System.arraycopy(buf, pos, b, off, n);
            pos += n;
            return n;
        }

        public int available() throws IOException {
            return (len - pos) + in.available();
        }
    }

    /** 一条连接的全部上下文，避免几个处理方法之间传一长串参数。 */
    private static final class Ctx {
        Socket client;
        BufIn cin;
        OutputStream cout;
        Req req;
        byte[] head;
        String ep;
        int epp;
        int use;
        boolean gw;
        boolean gwDirect;
        String via;
    }

    private void handle(Socket client) {
        Socket upstream = null;
        try {
            client.setSoTimeout(60000);
            Ctx ctx = new Ctx();
            ctx.client = client;
            ctx.cin = new BufIn(client.getInputStream());
            ctx.cout = client.getOutputStream();
            ctx.head = ctx.cin.head();
            if (ctx.head == null) {
                close(client);
                return;
            }
            /* 整段解码一次（ISO-8859-1 是逐字节直拷），之后所有定位都在这一个 String 上
             * indexOf，不 split、不建行数组；实测比手写 byte 循环快 30% 以上。 */
            ctx.req = Req.of(new String(ctx.head, StandardCharsets.ISO_8859_1));

            String[] gwHost = {conf.httpIp, conf.httpsIp};
            int[] gwPort = {conf.httpPort, conf.httpsPort};
            boolean[] gwOn = {conf.httpOn, conf.httpsOn};
            boolean[] gwDirect = {conf.httpDirect, conf.httpsDirect};

            int slot = ctx.req.port == 80 ? 0 : 1;
            /* http_others=off → http 模块整个关掉，80 端口直接直连（不发 CONNECT、不注入）；
             * 开着但没填 http_ip → 交给 https 槽，这就是原版「http_ip 空 → http 由 https 接管」。
             * （sets() 里空的 HttpIp 会被填成哨兵 192.168.88.88，sock5_check 看到它就走 https 槽。） */
            int use = USE[slot][gwOn[0] ? 1 : 0][gwDirect[0] ? 1 : 0][gwHost[0].length() == 0 ? 1 : 0];
            boolean gw = GW[use][gwOn[use] ? 1 : 0][gwDirect[use] ? 1 : 0][gwHost[use].length() == 0 ? 1 : 0];
            /* the gateway itself may be a domain (most 免流 configs use one) and the local resolver
               is exactly what dns_url exists to bypass — resolve it through the same channel */
            String ep = gw ? resolveGateway(gwHost[use]) : dns.resolveOr(ctx.req.host, ctx.req.host);
            if (ep == null) {
                log("inj DNS 拒绝解析 " + ctx.req.host + "：当前策略不是直连，"
                        + "注入器的网关 bootstrap 没有代理解析通道");
                close(client);
                return;
            }
            ctx.ep = ep;
            ctx.epp = gw ? gwPort[use] : ctx.req.port;
            ctx.use = use;
            ctx.gw = gw;
            ctx.gwDirect = gwDirect[use];
            ctx.via = (slot == 0 && use == 1) ? "（http 交给 https 槽）" : "";

            int path = PATH[slot][use][gw ? 1 : 0];
            if (path == 2) {
                upstream = httpSlot(ctx);
            } else if (path == 1) {
                upstream = gatewayTunnel(ctx);
            } else {
                upstream = directTunnel(ctx);
            }
        } catch (Exception e) {
            boolean normalClose = e instanceof java.net.SocketException
                    && (String.valueOf(e.getMessage()).contains("Socket closed")
                    || String.valueOf(e.getMessage()).contains("Connection reset"));
            lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
            if (!normalClose) log("inj error: " + lastError);
            close(client);
            close(upstream);
        }
    }

    /** 网关大多写成域名，而 dns_url 就是要绕开本地解析：先走配置里那台 DNS（HTTPDNS / DoH /
     *  明文 DNS / DoT），拿不到就原样返回、交给系统解析。 */
    private String resolveGateway(String host) {
        if (isIp(host)) return host;
        return dns.resolveOr(host, host);
    }

    /** 网关本来就是 IP 时不用解析；域名才值得走 dns_url / HTTPDNS 那两条路。 */
    static boolean isIp(String h) {
        return HttpDns.isIp(h);
    }

    /** 没有网关（或 _direct=on）：连目标，回 200，之后纯转发一个字节都不改。 */
    private Socket directTunnel(Ctx c) throws IOException {
        Socket up = new Socket();
        up.setSoTimeout(30000);
        up.connect(new InetSocketAddress(c.ep, c.epp), 10000);
        up.setTcpNoDelay(true);
        /* xray 的 http 出站发完 CONNECT 就在等这一行；不给它，隧道永远不开始。
         * 注意这行只写回给客户端（xray），一个字节都不往目标发。 */
        c.cout.write("HTTP/1.1 200 Connection established\r\n\r\n"
                .getBytes(StandardCharsets.ISO_8859_1));
        c.cout.flush();
        log("inj CONNECT " + c.req.host + ":" + c.req.port + " → " + c.ep + ":" + c.epp
                + " 直连" + (c.gwDirect ? "（_direct=on）"
                : "（这一侧没有可用网关，会走真实网络）") + c.via);
        startDown(up, c.cout, c.client, up.getInputStream());
        pumpUp(c.cin, up.getOutputStream());
        close(up);
        close(c.client);
        return null;
    }

    /** 经网关 CONNECT。 */
    private Socket gatewayTunnel(Ctx c) throws Exception {
        String target = c.req.host + ":" + c.req.port;
        /* 已经确认网关不认这个目标（或者不认 v6），就别再敲它了 */
        if (gwNoV6 && c.req.host.indexOf(':') >= 0) {
            if (note("nov6|" + c.req.host)) {
                log("inj CONNECT " + target + " 跳过：免流网关已两次拒绝 IPv6 目标，"
                        + "这个网关只能跑 v4");
            }
            close(c.client);
            return null;
        }
        if (!allow(target)) {
            if (note("cool|" + target)) {
                log("inj CONNECT " + target + " 暂缓：" + FAIL_LIMIT + " 次失败后冷却 "
                        + (COOLDOWN_MS / 1000) + " 秒，期间直接本地拒绝");
            }
            close(c.client);
            return null;
        }
        Conn conn = openConnect(c.ep, c.epp, c.req.host, c.req.port, c.req.version);
        if (conn == null) {
            markFail(target, c.req.host);
            String k = "fail|" + c.req.host + ":" + c.req.port + "|" + c.ep + ":" + c.epp;
            if (note(k)) {
                int hits = hits(k);
                log("inj CONNECT " + c.req.host + ":" + c.req.port + " → " + c.ep + ":" + c.epp
                        + " 失败（" + lastHandshake + "）"
                        + (hits > 1 ? "，同一目标已累计 " + hits + " 次" : ""));
            }
            close(c.client);
            return null;
        }
        markOk(target);
        c.cout.write("HTTP/1.1 200 Connection established\r\n\r\n"
                .getBytes(StandardCharsets.ISO_8859_1));
        c.cout.flush();
        log("inj CONNECT " + c.req.host + ":" + c.req.port + " → " + c.ep + ":" + c.epp
                + (strategy == 2 ? " ok(plain)" : " ok(tpl)") + c.via);
        startDown(conn.s, c.cout, c.client, conn.in);
        pumpUp(c.cin, conn.s.getOutputStream());
        close(conn.s);
        close(c.client);
        return null;
    }

    /** http slot: open the endpoint, answer the tunnel, then rewrite request heads. */
    private Socket httpSlot(Ctx c) throws Exception {
        Socket up = new Socket();
        up.setSoTimeout(30000);
        up.connect(new InetSocketAddress(c.ep, c.epp), 10000);
        up.setTcpNoDelay(true);
        OutputStream uout = up.getOutputStream();
        byte[] inner = c.head;
        if (c.req.tunnel()) {
            c.cout.write("HTTP/1.1 200 Connection established\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            c.cout.flush();
            inner = c.cin.head();
            if (inner == null) {
                close(c.client);
                close(up);
                return null;
            }
        }
        startDown(up, c.cout, c.client, up.getInputStream());
        httpRelay(c.cin, uout, new String(inner, StandardCharsets.ISO_8859_1), c.gw, c.ep, c.epp);
        pumpUp(c.cin, uout);
        close(up);
        close(c.client);
        return null;
    }

    /** CONNECT handshake. Each attempt opens a fresh socket: a gateway that rejects the injected
     *  line usually closes the connection, so retrying on it would be talking to a dead socket. */
    /** 一条握好手的上游连接：socket + 已经读掉状态行的输入流（不能再从 socket 上重新取，
     *  否则缓冲里的字节就丢了）。 */
    static final class Conn {
        Socket s;
        InputStream in;
    }

    private Conn openConnect(String ep, int epp, String host, int port, String version) throws Exception {
        String plain = host + ":" + port;
        String tpl = conf.httpsFirst;
        boolean haveTpl = tpl.length() > 0;
        /* 默认只用用户配置的握手方式：模板被拒就是没网，不偷偷换成普通 CONNECT 掩盖配置错误 */
        if (!haveTpl) {
            attempt(2, ep, epp, plain, version);
            return finish(host, port);
        }
        boolean tplOk = System.currentTimeMillis() - tplFailAt > 30000;
        boolean plainOk = System.currentTimeMillis() - plainFailAt > 30000;
        int[] order = conf.injectFallback
                ? ORDER[strategy][tplOk ? 1 : 0][plainOk ? 1 : 0]
                : ORDER[1][1][0];
        /* 最多两种尝试，展开成两次调用：没有循环，也没有 order.length 判断。 */
        Conn c = attempt(order[0], ep, epp, plain, version);
        if (c == null && order.length == 2) c = attempt(order[1], ep, epp, plain, version);
        if (c != null) return c;
        return finish(host, port);
    }

    private Conn finish(String host, int port) {
        lastError = lastHandshake;
        failCount++;
        lastFailLine = host + ":" + port + " → " + lastHandshake
                + (conf.injectFallback ? "（已尝试回退）" : "（模板被拒，未回退）");
        return null;
    }

    private Conn attempt(int kind, String ep, int epp, String plain, String version) {
        boolean useTpl = kind == 1;
        Socket up = null;
        String block = useTpl
                ? sealed(render(conf.httpsFirst, "CONNECT", plain, "", version))
                : sealed("CONNECT " + plain + " " + version + "\r\nHost: " + plain
                + "\r\nUser-Agent: " + UA);
        try {
            up = new Socket();
            up.setSoTimeout(30000);
            up.connect(new InetSocketAddress(ep, epp), 10000);
            up.setTcpNoDelay(true);
            up.getOutputStream().write(block.getBytes(StandardCharsets.ISO_8859_1));
            up.getOutputStream().flush();
            BufIn pin = new BufIn(up.getInputStream());
            String line = pin.line();
            int code = statusOf(line);
            boolean ok = code / 100 == 2;
            String label = useTpl ? "tpl" : "plain";
            lastHandshake = label + " " + (code == 0 ? "无响应" : String.valueOf(code));
            if (ok) {
                swallowBlank(pin);
                strategy = useTpl ? 1 : 2;
                failCount = 0;
                log("  handshake " + label + " → " + head0(line) + " ok");
                Conn c = new Conn();
                c.s = up;
                c.in = pin;
                return c;
            }
            if (useTpl) tplFailAt = System.currentTimeMillis();
            else plainFailAt = System.currentTimeMillis();
            /* 同一个目标同样的结果，一分钟内只留一条 */
            String k = "hs|" + plain + "|" + lastHandshake;
            if (note(k)) {
                int hit = hits(k);
                log("  handshake " + label + " → " + head0(line) + " 拒绝"
                        + (hit > 1 ? "（同一目标累计 " + hit + " 次）" : ""));
                log("   sent: " + brief(block));
                if (code == 503) {
                    log("  网关 " + ep + ":" + epp + " 拒绝转发到 " + plain
                            + " —— 免流网关只放行它认可的域名/端口，跟本机、跟协议都没关系。"
                            + "链路里下一跳的地址被拒时整条链路都不通："
                            + "换到 80/443 的普通域名（或用 CDN 反代），或者把注入这一跳去掉");
                }
            }
        } catch (Exception e) {
            String label = useTpl ? "tpl" : "plain";
            /* 以前这里不写 lastHandshake，上层只能干巴巴报一句"握手失败" */
            lastHandshake = label + " " + e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : " " + e.getMessage());
            if (useTpl) tplFailAt = System.currentTimeMillis();
            else plainFailAt = System.currentTimeMillis();
            String k = "hs|" + plain + "|" + lastHandshake;
            if (note(k)) {
                int hit = hits(k);
                log("  handshake " + label + " → " + e.getClass().getSimpleName()
                        + (hit > 1 ? "（同一目标累计 " + hit + " 次）" : ""));
                log("   sent: " + brief(block));
            }
        }
        close(up);
        return null;
    }

    /** 标准 HTTP 代理会在状态行后再补一个空行，那个 CRLF 绝不能漏给客户端（TLS 第一个字节就错了）。
     *  只看已经躺在缓冲区里的字节，等不到就认为这家网关不回空行，绝不为此阻塞。 */
    private static void swallowBlank(BufIn in) {
        try {
            for (int i = 0; i < 4 && in.available() < 1; i++) Thread.sleep(5);
            if (in.available() < 1) return;
            int a = in.read();
            if (a == '\n') return;                       /* 单独一个 LF，当空行吃掉 */
            if (a != '\r') {
                in.unread(a);
                return;
            }
            if (in.available() < 1) {
                in.unread(a);
                return;
            }
            int b = in.read();
            if (b == '\n') return;                       /* CRLF：吃掉 */
            in.unread(b);
            in.unread(a);
        } catch (Exception ignored) {
        }
    }

    /** HTTP status of a response head: only the status line counts. Naive substring matching
     *  ("contains 2") is wrong because headers carry dates and lengths too.
     *  状态行可能没有原因短语（"HTTP/1.1 200\r\n"），line() 交进来的串还带着 CRLF：
     *  数字后面遇到空白或行尾就收尾，不能当成非法字符整行作废。 */
    public static int statusOf(String head) {
        int sp = head.indexOf(' ');
        if (sp < 0) return 0;
        int end = head.indexOf(' ', sp + 1);
        if (end < 0) end = head.length();
        int code = 0;
        int digits = 0;
        for (int i = sp + 1; i < end; i++) {
            char ch = head.charAt(i);
            int c = ch - '0';
            if (c < 0 || c > 9) {
                if (digits == 0) continue;               /* 前导空白 */
                if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') break;
                return 0;
            }
            code = code * 10 + c;
            digits++;
        }
        return digits == 3 ? code : 0;
    }

    private static String head0(String s) {
        int e = s.indexOf("\r\n");
        String line = e > 0 ? s.substring(0, e) : s;
        return line.length() > 56 ? line.substring(0, 56) : line;
    }

    /** One log line for what the gateway actually received. */
    static String brief(String block) {
        String s = block.replace("\r\n", " | ").trim();
        return s.length() > 120 ? s.substring(0, 120) : s;
    }

    /* --------------------------------------------------------------- helpers */

    /** [M] method, [H] host (host:port for CONNECT, Host header for http),
     *  [U] request target, [V] version — plus every original alias.
     *  单趟扫描：命中一个占位符就跳过整个 token，不再对整串做 8 次 replace。 */
    public static String render(String template, String method, String host, String uri, String version) {
        /* 别名 [M]/[m] 落到同一个值：id >> 1 就是值槽，四个元素的表，不再每次建八格数组。 */
        String[] v = {method, host, uri, version};
        StringBuilder out = new StringBuilder(template.length() + 64);
        int n = template.length();
        int i = 0;
        /* 用 indexOf 整段跳过普通字符，只在命中占位符时插入值：
         * 逐字符 append 虽然也是单趟，但把整串复制拆成了上千次调用。 */
        while (true) {
            int open = template.indexOf('[', i);
            if (open < 0) {
                out.append(template, i, n);
                break;
            }
            int close = template.indexOf(']', open + 1);
            if (close < 0 || close - open > 9) {
                out.append(template, i, open + 1);
                i = open + 1;
                continue;
            }
            int id = token(template, open + 1, close);
            if (id < 0) {
                out.append(template, i, close + 1);
                i = close + 1;
                continue;
            }
            out.append(template, i, open).append(v[id >> 1]);
            i = close + 1;
        }
        return sealed(noBlank(out.toString()));
    }

    /** 占位符 → 值槽下标；返回 -1 表示不是占位符。 */
    private static int token(String t, int from, int to) {
        switch (to - from) {
            case 1:
                char c = t.charAt(from);
                if (c == 'M') return 0;
                if (c == 'H') return 2;
                if (c == 'U') return 4;
                if (c == 'V') return 6;
                return -1;
            case 3:
                return t.regionMatches(from, "uri", 0, 3) ? 5 : -1;
            case 4:
                return t.regionMatches(from, "host", 0, 4) ? 3 : -1;
            case 6:
                return t.regionMatches(from, "method", 0, 6) ? 1 : -1;
            case 7:
                return t.regionMatches(from, "version", 0, 7) ? 7 : -1;
            default:
                return -1;
        }
    }

    /** doConnect deletes every blank line the user typed into the template before it seals it:
     *  headers are meant to run on consecutive lines, the terminal blank line is ours. */
    private static String noBlank(String s) {
        /* 用 indexOf/replace 整段处理：模板结尾本来就带一个空行，逐字符重建反而是最慢的分支。
         * 语义与原版 doConnect 完全一致（只折叠 CRLFCRLF 与 LFLF）。 */
        while (s.contains("\r\n\r\n")) s = s.replace("\r\n\r\n", "\r\n");
        while (s.contains("\n\n")) s = s.replace("\n\n", "\n");
        return s;
    }

    /** Every original template ends in exactly one blank line (doConnect fixes it up by hand). */
    public static String sealed(String s) {
        int n = s.length();
        while (n > 0) {
            char c = s.charAt(n - 1);
            if (c != '\r' && c != '\n') break;
            n--;
        }
        return s.substring(0, n) + "\r\n\r\n";
    }

    /** 一个 sealed 的头 + 客户端原本的 body 框架头（0 = 没有 body，<0 = chunked）。 */
    static String withFraming(String sealedHead, int body) {
        if (body == 0) return sealedHead;
        String framing = body < 0 ? "Transfer-Encoding: chunked\r\n"
                : "Content-Length: " + body + "\r\n";
        return sealedHead.substring(0, sealedHead.length() - 2) + framing + "\r\n";
    }

    /** host:port → host. A Host header almost always carries the port, and CONNECT needs the bare
     *  host so that host + ":" + port does not come out as host:443:443. */
    private static String bareHost(String authority) {
        String a = authority;
        int userinfo = a.indexOf('@');
        if (userinfo >= 0) a = a.substring(userinfo + 1);
        int colon = a.lastIndexOf(':');
        int bracket = a.lastIndexOf(']');
        return colon > bracket && colon > 0 ? a.substring(0, colon) : a;
    }

    private static String hostOf(String target, String hostHeader) {
        int s = target.indexOf("://");
        String auth = target;
        if (s >= 0) {
            String rest = target.substring(s + 3);
            int slash = rest.indexOf('/');
            auth = slash < 0 ? rest : rest.substring(0, slash);
        } else if (hostHeader.length() > 0) {
            auth = hostHeader;
        }
        return bareHost(auth);
    }

    private static String pathOf(String target) {
        int s = target.indexOf("://");
        if (s < 0) return target;
        int slash = target.indexOf('/', s + 3);
        return slash < 0 ? "/" : target.substring(slash);
    }

    private static int portOf(String target, int kind) {
        int s = target.indexOf("://");
        String authority = target;
        if (s >= 0) {
            String rest = target.substring(s + 3);
            int slash = rest.indexOf('/');
            authority = slash < 0 ? rest : rest.substring(0, slash);
        }
        int colon = authority.lastIndexOf(':');
        int bracket = authority.lastIndexOf(']');
        int p = colon > bracket && colon > 0 ? intOf(authority.substring(colon + 1), 0) : 0;
        return p > 0 ? p : kind == 1 ? 443 : 80;
    }

    /** [from,to) 全是空格？ */
    private static boolean blank(String text, int from, int to) {
        for (int i = from; i < to; i++) if (text.charAt(i) != ' ') return false;
        return true;
    }

    /** [from,to) 内第一个空格的位置，没有返回 -1。 */
    private static int space(String text, int from, int to) {
        for (int i = from; i < to; i++) if (text.charAt(i) == ' ') return i;
        return -1;
    }

    /** 在整段头里找某个头名，不再 split 出行数组；返回最后一个匹配（和原实现一致）。 */
    private static String headerValue(String text, int firstEnd, String name) {
        String out = "";
        int i = firstEnd;
        while (i < text.length()) {
            if (text.startsWith("\r\n", i)) i += 2;
            if (i >= text.length()) break;
            int e = text.indexOf("\r\n", i);
            if (e < 0) e = text.length();
            int c = text.indexOf(':', i);
            if (c > i && c < e) {
                int ns = i;
                int ne = c;
                /* String.trim 去掉的是所有 <= ' ' 的字符，不只是空格和制表符 */
                while (ns < ne && text.charAt(ns) <= ' ') ns++;
                while (ne > ns && text.charAt(ne - 1) <= ' ') ne--;
                if (ne - ns == name.length() && text.regionMatches(true, ns, name, 0, name.length())) {
                    out = text.substring(c + 1, e).trim();
                }
            }
            i = e + 2;
        }
        return out;
    }

    private static int intOf(String s, int def) {
        int v = 0;
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i) - '0';
            if (c < 0 || c > 9) return def;
            v = v * 10 + c;
        }
        return s.length() == 0 ? def : v;
    }

    /** 一次扫描读完整个头；状态转移走 256 项表，读的时候一块一块拿（pushback 负责把多读的
     *  字节还回去），避免每条连接上千次单字节 read()。 */
    /** Rewrites every request head in the client stream, leaving bodies untouched: once a head
     *  carries a body (or framing we do not model) the rest of the direction goes through raw,
     *  so a POST body that happens to contain "GET " is never mangled. */
    private void httpRelay(BufIn cin, OutputStream uout, String first, boolean gw,
                           String ep, int epp) throws IOException {
        String tpl = conf.httpFirst;
        String head = first;
        while (true) {
            Req in = Req.of(head);
            String block = tpl.length() > 0 ? httpmod(head)
                    : gw ? head
                    : withFraming(sealed(in.method + " " + pathOf(in.target) + " " + in.version),
                    bodyOf(head));
            uout.write(block.getBytes(StandardCharsets.ISO_8859_1));
            uout.flush();
            log("inj HTTP " + in.method + " " + in.target + " → " + ep + ":" + epp
                    + (tpl.length() > 0 ? " tpl" : gw ? " raw" : " direct"));
            log("  sent: " + brief(block));
            if (bodyOf(head) != 0) return;
            byte[] next = cin.head();
            if (next == null) return;
            String text = new String(next, StandardCharsets.ISO_8859_1);
            if (!looksRequest(text)) {
                uout.write(next);
                return;
            }
            head = text;
        }
    }

    /** 原版 SocketThreadOutput.httpmod 的语义：**只把首行换成模板**，客户端其余请求头原样保留，
     *  `http_del` 里列的名字（逗号或分号分隔）连同它的值一起删掉。模板自己也写了的头名要去重，
     *  否则会出两个 Host —— 那比丢头更糟。以前整块顶掉，Cookie / Range / Referer / UA 全丢，
     *  带鉴权的图片和 CDN 请求就是这么挂的。 */
    private String httpmod(String head) {
        Req in = Req.of(head);
        String rendered = render(conf.httpFirst, in.method,
                in.hostHeader.length() > 0 ? in.hostHeader : in.host,
                in.target.length() == 0 ? "/" : in.target, in.version);
        /* 去掉结尾所有换行：模板可能自带 \r\n，最后那个空行由我们统一补，
         * 多留一个会把头块提前截断，后面的请求头全变成 body。 */
        int end = rendered.length();
        while (end > 0 && (rendered.charAt(end - 1) == '\n' || rendered.charAt(end - 1) == '\r')) end--;
        String block = rendered.substring(0, end);
        int e = block.indexOf("\r\n");
        String firstLine = e < 0 ? block : block.substring(0, e);
        String tplHeaders = e < 0 ? "" : block.substring(e + 2);

        /* 模板头名 + http_del 合成一张删除表：数量很小，线性比较比建 HashSet 更快。 */
        ArrayList<String> drop = new ArrayList<String>(httpDrop.length + 4);
        for (String d : httpDrop) drop.add(d);
        int p = 0;
        while (p < tplHeaders.length()) {
            int le = tplHeaders.indexOf("\r\n", p);
            if (le < 0) le = tplHeaders.length();
            int c = tplHeaders.indexOf(':', p);
            if (c > p && c < le) drop.add(tplHeaders.substring(p, c).trim().toLowerCase(Locale.ROOT));
            p = le + 2;
        }

        StringBuilder sb = new StringBuilder(head.length() + 128);
        sb.append(firstLine).append("\r\n");
        if (tplHeaders.length() > 0) sb.append(tplHeaders).append("\r\n");
        int start = e < 0 ? head.length() : e + 2;
        int i = start;
        while (i < head.length()) {
            int le = head.indexOf("\r\n", i);
            if (le < 0) le = head.length();
            int c = head.indexOf(':', i);
            while (c > i && head.charAt(c - 1) == ' ') c--;
            boolean keep = true;
            for (int d = 0; d < drop.size(); d++) {
                int n = drop.get(d).length();
                if (c > i && c - i == n && head.regionMatches(true, i, drop.get(d), 0, n)) {
                    keep = false;
                    break;
                }
            }
            if (keep && le > i) sb.append(head, i, le).append("\r\n");
            i = le + 2;
        }
        sb.append("\r\n");
        return sb.toString();
    }

    private static boolean looksRequest(String head) {
        int e = head.indexOf("\r\n");
        if (e < 0) e = head.length();
        int s1 = head.indexOf(' ');
        if (s1 <= 0 || s1 >= e) return false;
        int s2 = head.indexOf(' ', s1 + 1);
        if (s2 <= s1 || s2 >= e) return false;
        if (!head.startsWith("HTTP/", s2 + 1)) return false;
        return methodId(head.substring(0, s1).toUpperCase(Locale.ROOT)) >= 0;
    }

    /** 0 = no body at all, n = exactly n bytes, -1 = chunked (which we do not model). */
    private static int bodyOf(String head) {
        int e = head.indexOf("\r\n");
        String te = headerValue(head, e < 0 ? head.length() : e, "transfer-encoding").toLowerCase(Locale.ROOT);
        if (te.contains("chunked")) return -1;
        return intOf(headerValue(head, e < 0 ? head.length() : e, "content-length"), 0);
    }

    private void startDown(final Socket up, final OutputStream cout, final Socket client,
                                  final InputStream uin) {
        /* 下行同样走池子：以前每条连接再 new 一个线程，一条 HTTP 请求就是两个线程。 */
        boolean ok = submit(new Runnable() {
            public void run() {
                try {
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = uin.read(buf)) > 0) {
                        cout.write(buf, 0, n);
                        cout.flush();
                    }
                } catch (Exception ignored) {
                }
                close(client);
                close(up);
            }
        });
        if (!ok) {
            close(client);
            close(up);
        }
    }

    private static void pumpUp(InputStream cin, OutputStream uout) {
        try {
            byte[] buf = new byte[16384];
            int n;
            while ((n = cin.read(buf)) > 0) {
                uout.write(buf, 0, n);
                uout.flush();
            }
        } catch (Exception ignored) {
        }
    }

    private static void close(Socket s) {
        try {
            if (s != null) s.close();
        } catch (Exception ignored) {
        }
    }
}
