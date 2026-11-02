package hev.htproxy;

/**
 * JNI binding for hev-socks5-tunnel 2.19.3.
 *
 * <p>src/hev-jni.c registers its natives to this exact class when the library is
 * loaded (JNI_OnLoad -> FindClass(PKGNAME "/" CLSNAME) + RegisterNatives), with
 * PKGNAME/CLSNAME defaulting to hev/htproxy + TProxyService. Renaming this class
 * requires rebuilding the .so with other PKGNAME/CLSNAME values.
 */
public final class TProxyService {
    private TProxyService() {
    }

    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    public static native boolean TProxyStartService(String config_path, int fd);

    public static native boolean TProxyStopService();

    public static native boolean TProxyIsRunning();

    public static native long[] TProxyGetStats();
}
