import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


public class PemKeystoreTestUtils {

    private static final String DIR = System.getProperty("test.src", ".");
    private static final String FILE_SEPARATOR = System.getProperty("file.separator");

    static InputStream getResource(String name) throws IOException {
        return new FileInputStream(new File(DIR + FILE_SEPARATOR + "files", name));
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
/*

static PrivateKey readPrivateKey(File keyFile, String algorithm, String password) throws Exception {
    String pemKey = Files.readAllLines(keyFile.toPath()).stream().filter(s -> !s.startsWith("-----"))
    .collect(Collectors.joining(""));
    byte[] encoding = Base64.getDecoder().decode(pemKey);

    AlgorithmParameters nullAlgorithmParam = AlgorithmParameters.getInstance("0.1", JctProvider.getInstance());
    EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(nullAlgorithmParam, encoding);
    Cipher nullCipher = Cipher.getInstance("null", JctProvider.getInstance());
    nullCipher.init(Cipher.DECRYPT_MODE, new NullPrivateKey());
    PKCS8EncodedKeySpec spec = epki.getKeySpec(nullCipher);

    KeyFactory kf = KeyFactory.getInstance(spec.getAlgorithm());

    return kf.generatePrivate(spec);
}

static X509Certificate readCertificate(File certFile) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    try (FileInputStream fis = new FileInputStream(certFile)) {
        return (X509Certificate) cf.generateCertificate(fis);
    }
}

static void assertFilesEqual(File expectedFile, File realFile) throws Exception {
    assertFilesEqual(expectedFile.toPath(), realFile.toPath());
}

static void assertFilesEqual(Path expectedPath, Path realPath) throws Exception {
    Assertions.assertArrayEquals(Files.readAllBytes(expectedPath), Files.readAllBytes(realPath));
}
*/

}