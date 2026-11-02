import com.android.apksig.ApkSigner;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/** Minimal apksigner replacement: v1+v2+v3 schemes via the apksig library. */
public class Sign {
    public static void main(String[] args) throws Exception {
        File in = new File(args[0]);
        File out = new File(args[1]);
        String ksPath = args[2];
        String pass = args[3];
        String alias = args[4];

        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream fis = new FileInputStream(ksPath);
        ks.load(fis, pass.toCharArray());
        fis.close();
        PrivateKey key = (PrivateKey) ks.getKey(alias, pass.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(cert);

        ApkSigner signer = new ApkSigner.Builder()
                .setInputApk(in)
                .setOutputApk(out)
                .setSignerConfig(new ApkSigner.SignerConfig.Builder(alias, key, certs).build())
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build();
        signer.sign();
        System.out.println("signed -> " + out.getAbsolutePath() + " (" + out.length() + " bytes)");
    }
}
