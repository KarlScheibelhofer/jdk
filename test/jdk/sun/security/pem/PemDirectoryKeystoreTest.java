/*
 * TODO: Copyright goes here
 */

/*
 * @test
 * @summary check reading for PEM keystore files
 * @author  Karl Scheibelhofer
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicBoolean;


public class PemDirectoryKeystoreTest {

    private static final String PROVIDER = "SUN";

    public static void main(String[] args) throws Exception {
        loadTruststoreDirectory();
        System.out.println("OK: test loading truststore directory");

        loadTruststoreDirectoryShort();
        System.out.println("OK: test loading truststore directory short");

        storeTruststoreDirectory();
        System.out.println("OK: test storing truststore directory");

        testCreateRsaDirectoryKeystoreWithChain();
        System.out.println("OK: test storing keystore directory with RSA private key and certificate chain");

        loadTruststoreDirectoryFromFile();
        System.out.println("OK: test loading truststore directory from file");
    }

    private static void loadTruststoreDirectory() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        String caCertsDirPath = PemKeystoreTestUtils.getResourceFile("ca-certificates").getAbsolutePath();
        Path pemKeystoreDirFile = Files.createTempFile("ca-certificates", "pem-folder");

        Files.writeString(pemKeystoreDirFile, caCertsDirPath, StandardCharsets.UTF_8);

        try (FileInputStream is = new FileInputStream(pemKeystoreDirFile.toFile())) {
            ks.load(is, null);
        }
        Assertions.assertEquals(3, ks.size());
    }

    private static void loadTruststoreDirectoryShort() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        File caCertificatesFolder = PemKeystoreTestUtils.getResourceFile("ca-certificates");
        try (InputStream is = new ByteArrayInputStream(caCertificatesFolder.toString().getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }
        Assertions.assertEquals(3, ks.size());
    }

    private static void storeTruststoreDirectory() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);
        ks.load(null, null);

        Path caCertsDirPath = Files.createTempDirectory("truststore-dir");
        deleteDirectory(caCertsDirPath);

        Path pemKeystoreDirFile = Files.createTempFile("truststore", "pem-directory");

        Files.writeString(pemKeystoreDirFile, caCertsDirPath.toFile().getAbsolutePath(), StandardCharsets.UTF_8);

        try (FileInputStream is = new FileInputStream(pemKeystoreDirFile.toFile())) {
            ks.load(is, null);
        }

        ks.setCertificateEntry("test-root-ca-rsa", PemKeystoreTestUtils.getResourceCertificate("Test-Root-CA-RSA.crt"));
        ks.setCertificateEntry("test-intermediate-ca-rsa", PemKeystoreTestUtils.getResourceCertificate("Test-Intermediate-CA-RSA.crt"));
        ks.setCertificateEntry("test-root-ca-ec", PemKeystoreTestUtils.getResourceCertificate("Test-Root-CA-EC.crt"));
        ks.setCertificateEntry("test-intermediate-ca-ec", PemKeystoreTestUtils.getResourceCertificate("Test-Intermediate-CA-EC.crt"));

        final AtomicBoolean osClosed = new AtomicBoolean(false);
        OutputStream dummyOs = new OutputStream() {

            @Override
            public void write(int b) throws IOException {
                // empty
            }

            @Override
            public void close() {
                osClosed.set(true);
            }

        };

        // no output stream needed, if supplied, it is just closed
        ks.store(dummyOs, null);

        Assertions.assertTrue(osClosed.get());

        Assertions.assertTrue(Files.exists(caCertsDirPath));
        Assertions.assertTrue(Files.exists(caCertsDirPath.resolve("test-root-ca-rsa.crt")));
        Assertions.assertTrue(Files.exists(caCertsDirPath.resolve("test-intermediate-ca-rsa.crt")));
        Assertions.assertTrue(Files.exists(caCertsDirPath.resolve("test-root-ca-ec.crt")));
        Assertions.assertTrue(Files.exists(caCertsDirPath.resolve("test-intermediate-ca-ec.crt")));

        Path resourcesDir = PemKeystoreTestUtils.getResourceFile(".").toPath();
        Assertions.assertFilesEqual(resourcesDir.resolve("Test-Root-CA-RSA.crt"), caCertsDirPath.resolve("test-root-ca-rsa.crt"));
        Assertions.assertFilesEqual(resourcesDir.resolve("Test-Intermediate-CA-RSA.crt"), caCertsDirPath.resolve("test-intermediate-ca-rsa.crt"));
        Assertions.assertFilesEqual(resourcesDir.resolve("Test-Root-CA-EC.crt"), caCertsDirPath.resolve("test-root-ca-ec.crt"));
        Assertions.assertFilesEqual(resourcesDir.resolve("Test-Intermediate-CA-EC.crt"), caCertsDirPath.resolve("test-intermediate-ca-ec.crt"));
    }

    private static  void deleteDirectory(Path toBeDeleted) throws IOException {
        if (Files.exists(toBeDeleted)) {
            Files.walk(toBeDeleted)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
    }

    private static void testCreateRsaDirectoryKeystoreWithChain() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        Path pemKeystoreDirFile = Files.createTempDirectory("keystore-dir");
        try (InputStream is = new ByteArrayInputStream(
                pemKeystoreDirFile.toString().getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }

        File certFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA.crt");
        File caCertFile = PemKeystoreTestUtils.getResourceFile("Test-Intermediate-CA-RSA.crt");
        File rootCertFile = PemKeystoreTestUtils.getResourceFile("Test-Root-CA-RSA.crt");
        File keyFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA.pem");
        String alias = "www.doesnotexist.org-RSA";

        PrivateKey privateKey = PemKeystoreTestUtils.readPrivateKey(keyFile, "RSA", null);
        X509Certificate certificate = PemKeystoreTestUtils.readCertificate(certFile);
        X509Certificate caCertificate = PemKeystoreTestUtils.readCertificate(caCertFile);
        X509Certificate rootCertificate = PemKeystoreTestUtils.readCertificate(rootCertFile);

        Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate };
        ks.setKeyEntry(alias, privateKey, null, certChain);

        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            ks.store(os, null);
        }

        Assertions.assertTrue(Files.exists(pemKeystoreDirFile));
        Assertions.assertTrue(Files.exists(pemKeystoreDirFile.resolve("www.doesnotexist.org-RSA.crt")));
        Assertions.assertTrue(Files.exists(pemKeystoreDirFile.resolve("www.doesnotexist.org-RSA.pem")));

        Assertions.assertFilesEqual(keyFile.toPath(), pemKeystoreDirFile.resolve("www.doesnotexist.org-RSA.pem"));
        Assertions.assertArrayEquals(concat(certFile, caCertFile, rootCertFile), Files.readAllBytes(pemKeystoreDirFile.resolve("www.doesnotexist.org-RSA.crt")));
    }

    private static byte[] concat(File... fileArray) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(2048);
        for (File f : fileArray) {
            buffer.write(Files.readAllBytes(f.toPath()));
        }
        return buffer.toByteArray();
    }

    private static void loadTruststoreDirectoryFromFile() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        try (InputStream is = new ByteArrayInputStream(PemKeystoreTestUtils.getResourceFile("dummy-file").toString().getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }
        Assertions.assertThrowsExactly(IOException.class, () -> ks.store(null, null));
    }

/*
    private static void loadKeystoreDirectoryWithPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        try (InputStream is = new ByteArrayInputStream(
                "src/test/resources/dir-keystore".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }
        Assertions.assertEquals(1, ks.size());
        String alias = "www.doesnotexist.org-EC";

        assertTrue(ks.isKeyEntry(alias));
        assertNotNull(ks.getKey(alias, null));
        Certificate[] certChain = ks.getCertificateChain(alias);
        assertNotNull(certChain);
        assertEquals(1, certChain.length);
    }

    private static void loadKeystoreDirectoryWithEncPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        String password = "password";
        try (InputStream is = new ByteArrayInputStream(
                "src/test/resources/dir-keystore-enc".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, password.toCharArray());
        }
        Assertions.assertEquals(1, ks.size());
        String alias = "www.doesnotexist.org-EC-enc";

        assertTrue(ks.isKeyEntry(alias));
        assertNotNull(ks.getKey(alias, password.toCharArray()));
        Certificate[] certChain = ks.getCertificateChain(alias);
        assertNotNull(certChain);
        assertEquals(1, certChain.length);
    }

    private static void testInstance() throws Exception {
        assertNotNull(KeyStore.getInstance("pem", PROVIDER));
        assertNotNull(KeyStore.getInstance("PEM", PROVIDER));
        assertNotNull(KeyStore.getInstance("Pem", PROVIDER));

        assertNotNull(KeyStore.getInstance("pem-directory", PROVIDER));
        assertNotNull(KeyStore.getInstance("PEM-DIRECTORY", PROVIDER));
        assertNotNull(KeyStore.getInstance("Pem-Directory", PROVIDER));
    }

    private static void testInstallProvider() throws Exception {
        assertThat(Security.addProvider(PROVIDER), is(greaterThanOrEqualTo(0)));

        assertNotNull(KeyStore.getInstance("pem").getProvider().equals(PROVIDER));
        assertNotNull(KeyStore.getInstance("PEM").getProvider().equals(PROVIDER));
        assertNotNull(KeyStore.getInstance("Pem").getProvider().equals(PROVIDER));

        assertNotNull(KeyStore.getInstance("pem-directory").getProvider().equals(PROVIDER));
        assertNotNull(KeyStore.getInstance("PEM-DIRECTORY").getProvider().equals(PROVIDER));
        assertNotNull(KeyStore.getInstance("Pem-Directory").getProvider().equals(PROVIDER));

        Security.removeProvider(PROVIDER.getName());
    }

    private static void testBasename() throws Exception {
        assertEquals("dummy", PemDirectoryKeystore.getFileBasename(Path.of("dummy")));
        assertEquals("dummy", PemDirectoryKeystore.getFileBasename(Path.of("dummy.crt")));
    }

    private static void loadKeystoreDecryptWrongPassword() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        String password = "password";
        String wrongPassword = "secret";
        try (InputStream is = new ByteArrayInputStream("src/test/resources/dir-keystore-enc".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, wrongPassword.toCharArray());
        }
        Assertions.assertEquals(2, ks.size());
        String alias = "www.doesnotexist.org-EC-enc";

        assertTrue(ks.isKeyEntry(alias));
        assertNotNull(ks.getKey(alias, password.toCharArray()));
        Certificate[] certChain = ks.getCertificateChain(alias);
        assertNull(certChain);
        assertNotNull(ks.getCertificate(alias));
    }

    private static void loadKeystoreSpecial() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        assertThrowsExactly(IOException.class, () -> ks.load(new ByteArrayInputStream("src/test/resources/dir-keystore-special".getBytes(StandardCharsets.UTF_8)), null));
    }

    private static void loadKeystoreUnknown() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", PROVIDER);

        try (InputStream is = new ByteArrayInputStream("src/test/resources/dir-keystore-unknown".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }
        Assertions.assertEquals(0, ks.size());
    }
 */

}