package android.util;

/** JVM 测试替身：只实现项目用到的 encodeToString / decode，行为和 Android 的 Base64 对齐。 */
public final class Base64 {

    public static final int DEFAULT = 0;
    public static final int NO_WRAP = 2;
    public static final int URL_SAFE = 8;

    private Base64() {
    }

    public static String encodeToString(byte[] input, int flags) {
        java.util.Base64.Encoder e;
        if ((flags & NO_WRAP) != 0) {
            e = (flags & URL_SAFE) != 0 ? java.util.Base64.getUrlEncoder()
                    : java.util.Base64.getEncoder();
        } else {
            e = java.util.Base64.getMimeEncoder();
        }
        return e.encodeToString(input);
    }

    public static byte[] decode(String str, int flags) {
        String s = str.replaceAll("\\s", "");
        java.util.Base64.Decoder d = (flags & URL_SAFE) != 0
                ? java.util.Base64.getUrlDecoder() : java.util.Base64.getMimeDecoder();
        return d.decode(s);
    }
}
