package com.lcs.tproxy.model;

/**
 * 注入节点的 UDP 承载节点是「从列表里复制的副本」，和列表里的原节点是两份数据。
 *
 * <p>用户在编辑页选了某个节点后，副本连同注入节点一起写进 store.json；之后订阅更新、
 * 或用户改了原节点的地址/密码/传输，副本就会悄悄过期 —— 表面上 UDP 还走那个节点，
 * 实际连的是旧地址。这里在启动（读存档）和每次连网（Engine.start）时按
 * {@code udpSrcProfile / udpSrcIndex / udpSrcFp} 对一次账：
 * 原节点还在、配置变了，就用新配置覆盖副本；原节点没了就保留副本，不清空。
 *
 * <p>只有「复制保存」的节点才带来源三件套；动态引用（没有来源字段）直接跳过。
 */
public final class NodeSync {

    private NodeSync() {
    }

    /** @return 被同步的副本数量，0 表示列表没变 */
    public static int reconcile() {
        int changed = 0;
        for (Profile p : Store.I.profiles) {
            for (Node hop : p.chain) changed += reconcileHop(hop);
        }
        return changed;
    }

    /** 编辑页选中节点时记下来源，之后才能对账。 */
    public static void bindSource(Node host, String profileId, int index, Node source) {
        host.udpSrcProfile = profileId == null ? "" : profileId;
        host.udpSrcIndex = index;
        host.udpSrcFp = source == null ? "" : source.fingerprint();
    }

    private static int reconcileHop(Node host) {
        Node copy = host.udpNode;
        if (copy == null) return 0;
        if (host.udpSrcProfile.length() == 0 || host.udpSrcIndex < 0) return 0;  // 动态/旧存档
        Profile src = find(host.udpSrcProfile);
        if (src == null) return 0;                                              // 原配置已删：保留副本
        if (host.udpSrcIndex >= src.chain.size()) return 0;
        Node now = src.chain.get(host.udpSrcIndex);
        if (!Node.udpCapable(now.type) || now.kind() == Kinds.INJECT) return 0;  // 来源不再是 UDP 节点
        if (now == host) return 0;                                               // 指向自己：不动
        String fp = now.fingerprint();
        if (fp.equals(host.udpSrcFp)) return 0;
        host.udpNode = now.copy();
        host.udpSrcFp = fp;
        /* 原节点换了传输/关掉 uot 时，「经注入」可能已经不成立：退回直连，
         * 让启动日志里的提示去解释，而不是拿一份拨不通的配置硬跑。 */
        if (!Node.udpOverTcp(now) || now.netId() == Kinds.NET_KCP || now.netId() == Kinds.NET_QUIC) {
            host.udpViaInject = false;
        }
        return 1;
    }

    private static Profile find(String id) {
        for (Profile p : Store.I.profiles) if (p.id.equals(id)) return p;
        return null;
    }
}
