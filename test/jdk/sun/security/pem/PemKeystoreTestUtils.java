import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;


public class PemKeystoreTestUtils {

    static final String DIR = System.getProperty("test.src", ".");
    static final String FILE_SEPARATOR = System.getProperty("file.separator");

    static InputStream getResource(String name) throws IOException {
        return new FileInputStream(new File(DIR + FILE_SEPARATOR + "files", name));
    }

    static File getResourceFile(String name) throws IOException {
        return new File(DIR + FILE_SEPARATOR + "files", name);
    }

    static X509Certificate getResourceCertificate(String name) throws IOException, GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(getResource(name));
    }

    static boolean matching(PublicKey publicKey, PrivateKey privateKey) {
        if ((publicKey instanceof RSAPublicKey) && (privateKey instanceof RSAPrivateKey)) {
            return matching((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);
        }
        if ((publicKey instanceof ECPublicKey) && (privateKey instanceof ECPrivateKey)) {
            return matching((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
        }
        return false;
    }

    static boolean matching(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        return publicKey.getModulus().equals(privateKey.getModulus());
    }

    static boolean matching(ECPublicKey publicKey, ECPrivateKey privateKey) {
        try {
            // I found no better way using only Java standard API without additional
            // dependency
            byte[] data = new byte[32];
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(privateKey);
            s.update(data);
            byte[] sig = s.sign();
            s.initVerify(publicKey);
            s.update(data);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }


    static PrivateKey readPrivateKey(File keyFile, String algorithm, String password) throws Exception {
        String pemKey = Files.readAllLines(keyFile.toPath()).stream().filter(s -> !s.startsWith("-----")).collect(Collectors.joining(""));
        byte[] encoding = Base64.getDecoder().decode(pemKey);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoding);

        KeyFactory kf = KeyFactory.getInstance(algorithm);

        return kf.generatePrivate(spec);
    }

    static X509Certificate readCertificate(File certFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certFile)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

}