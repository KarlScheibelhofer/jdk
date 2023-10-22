import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


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