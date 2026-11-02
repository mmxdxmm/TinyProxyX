package com.lcs.tproxy.inject;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/** 反射打印 Req.of 的每个字段，用于两版对拍。 */
public final class ReqProbe {
    public static void main(String[] a) throws Exception {
        String[] cases = {
                "CONNECT 127.0.0.1:44577 HTTP/1.1\r\nHost: h\r\n\r\n",
                "CONNECT 127.0.0.1:44577 HTTP/1.1\r\nHost: 127.0.0.1:44577\r\n\r\n",
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
                "CONNECT example.com:443 HTTP/1.1\r\n\r\n",
                "GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
        };
        Class<?> c = Class.forName("com.lcs.tproxy.inject.InjectServer$Req");
        Method m = c.getDeclaredMethod("of", String.class);
        m.setAccessible(true);
        Field[] fs = c.getDeclaredFields();
        for (String s : cases) {
            Object r = m.invoke(null, s);
            StringBuilder b = new StringBuilder();
            for (Field f : fs) {
                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                f.setAccessible(true);
                b.append(f.getName()).append('=').append(f.get(r)).append(' ');
            }
            System.out.println(s.replace("\r\n", "\\n") + "\n    " + b);
        }
    }
}
