package com.lcs.tproxy.core;

import java.net.InetSocketAddress;
import java.net.ServerSocket;

public class Ports {
    public static int free() {
        try {
            ServerSocket s = new ServerSocket();
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress("127.0.0.1", 0));
            int p = s.getLocalPort();
            s.close();
            return p;
        } catch (Exception e) {
            return -1;
        }
    }

    /** TCP listeners only: UDP TPROXY readiness is checked by the root rule script. */
    public static boolean localOpen(int port, boolean udp) {
        return !udp && open("127.0.0.1", port);
    }

    public static boolean open(String host, int port) {
        try {
            java.net.Socket s = new java.net.Socket();
            s.connect(new InetSocketAddress(host, port), 1200);
            s.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
