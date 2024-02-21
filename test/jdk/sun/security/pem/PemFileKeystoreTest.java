/*
 * TODO: Copyright goes here
 */

/*
 * @test
 * @summary check reading for PEM keystore files
 * @author  Karl Scheibelhofer
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


public class PemFileKeystoreTest {

    private static final String PROVIDER = "SUN";

    public static void main(String[] args) throws Exception {
        testLoadPemTruststore();
        System.out.println("OK: test loading truststore file");

        testLoadPlainPrivateKeyRSA();
        System.out.println("OK: test loading plain RSA private-key");

        testLoadAes128EncryptedPrivateKeyRSA();
        System.out.println("OK: test loading AES-128 encrypted RSA private-key");

        testLoadAes256EncryptedPrivateKeyRSA();
        System.out.println("OK: test loading AES-256 encrypted RSA private-key");

        testLoadPlainPrivateKeyEC();
        System.out.println("OK: test loading plain EC private-key");

        testLoadAes128PrivateKeyEC();
        System.out.println("OK: test loading AES-128 encrypted EC private-key");

        testLoadAes256PrivateKeyEC();
        System.out.println("OK: test loading AES-256 encrypted EC private-key");

        testLoadRsaKeystoreWithChain();
        System.out.println("OK: test loading keystore with plain RSA private-key and certificate chain");

        testLoadEcKeystoreWithChain();
        System.out.println("OK: test loading keystore with plain EC private-key and certificate chain");

        testLoadRsaKeystoreChainAlias();
        System.out.println("OK: test loading keystore with RSA private-key and certificate chain and check alias");

        testStoreRsaKeystoreWithChain();
        System.out.println("OK: test storing keystore with RSA private-key and certificate chain");

        testCreateRsaKeystoreWithChain();
        System.out.println("OK: test create keystore with RSA private-key and certificate chain and alias names");

        testCreateRsaKeystoreWithChainAndPW();
        System.out.println("OK: test create keystore with RSA private-key and certificate chain and with password");

        testCreateTrustKeystore();
        System.out.println("OK: test create truststore");

        testDeleteKeyAndChain();
        System.out.println("OK: test deleting key entry with chain in keystore");

        testCreationDate();
        System.out.println("OK: test creation date in keystore");

        testGetCertificateAlias();
        System.out.println("OK: test alias names in truststore");

        testGetCertificateChainAlias();
        System.out.println("OK: test getting alias names of certificate in truststore");

        testGetCertificateAliasEmptyChain();
        System.out.println("OK: test loading keystore with private key and empty certificate chain");

        testReadAlias();
        System.out.println("OK: test loading keystore with private key and certificate chain with alias names specified");

        testStorePemTruststore();
        System.out.println("OK: test storing truststore with certificates");

        testStoreEncryptedRSAKey();
        System.out.println("OK: test storing a pre-encrypted key with certificate chain");

        loadMozillaRootStore4TLS();
        System.out.println("OK: test loading a Mozilla truststore");

        testLoadPemTruststoreAliasExplanatory();
        System.out.println("OK: test loading a truststore with alias names and explanatory entries");

        testGetViaAlias();
        System.out.println("OK: test loading a truststore and getting entries via alias names");

        testLoadEnc();
        System.out.println("OK: test getting an encrypted key entries without password fails");

        testUnsupportedKey();
        System.out.println("OK: test setting unsupported key entries");

        testUnsupportedCertificate();
        System.out.println("OK: test setting unsupported certificate entries");
    }

    private static void testLoadPemTruststore() throws Exception {
        final String storeName = "truststore.pem";

        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);

        Assertions.assertNotNull(ks, "keystore is null");

        ks.load(PemKeystoreTestUtils.getResource(storeName), null);
        Assertions.assertEquals(4, ks.size());

        Set<Certificate> certSet = new HashSet<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        certSet.add(cf.generateCertificate(PemKeystoreTestUtils.getResource("github.com.crt")));
        certSet.add(cf.generateCertificate(PemKeystoreTestUtils.getResource("google.com.crt")));
        certSet.add(cf.generateCertificate(PemKeystoreTestUtils.getResource("microsoft.com.crt")));
        certSet.add(cf.generateCertificate(PemKeystoreTestUtils.getResource("orf.at.crt")));

        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            if (ks.isCertificateEntry(alias)) {
                Certificate c = ks.getCertificate(alias);
                Assertions.assertNotNull(c);
                Assertions.assertTrue(certSet.contains(c));
                if (c instanceof X509Certificate) {
                    X509Certificate xc = (X509Certificate) c;
                    String subjectDN = xc.getSubjectX500Principal().getName();
                    Assertions.assertEquals(subjectDN, alias);
                } else {
                    Assertions.fail("invalid cert type");
                }
            } else {
                Assertions.fail("found unexpected non-certificate entry with alias: " + alias);
            }
        }
    }

    static void checkPrivateKey(String keyStoreFile, String keyStoreType, char[] privateKeyPassword,
                                Class<? extends PrivateKey> expectedPrivateKeyClass) throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        Assertions.assertNotNull(ks);

        ks.load(PemKeystoreTestUtils.getResource(keyStoreFile), null);
        Assertions.assertEquals(1, ks.size());

        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            if (!ks.isKeyEntry(alias)) {
                Assertions.fail();
            }
            Key k = ks.getKey(alias, privateKeyPassword);
            Assertions.assertNotNull(k);
            if (!expectedPrivateKeyClass.isAssignableFrom(k.getClass())) {
                Assertions.fail();
            }
        }
    }

    private static void testLoadPlainPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048.pem", "pem", null, RSAPrivateKey.class);
    }

    private static void testLoadAes128EncryptedPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048-aes128.pem", "pem", "password".toCharArray(), RSAPrivateKey.class);
    }

    private static void testLoadAes256EncryptedPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048-aes256.pem", "pem", "password".toCharArray(), RSAPrivateKey.class);
    }

    private static void testLoadPlainPrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256.pem", "pem", null, ECPrivateKey.class);
    }

    private static void testLoadAes128PrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256-aes128.pem", "pem", "password".toCharArray(), ECPrivateKey.class);
    }

    private static void testLoadAes256PrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256-aes256.pem", "pem", "password".toCharArray(), ECPrivateKey.class);
    }

    private static void testLoadRsaKeystoreWithChain() throws Exception {
        checkKeystoreWithChain("RSA");
    }

    private static void testLoadEcKeystoreWithChain() throws Exception {
        checkKeystoreWithChain("EC");
    }

    private static void checkKeystoreWithChain(String algorithm) throws Exception {
        String keyStoreFile = "www.doesnotexist.org-" + algorithm + "-keystore.pem";
        String keyStoreType = "pem";
        char[] privateKeyPassword = "password".toCharArray();

        KeyStore ks = KeyStore.getInstance(keyStoreType, PROVIDER);
        Assertions.assertNotNull(ks);

        ks.load(PemKeystoreTestUtils.getResource(keyStoreFile), null);
        Assertions.assertEquals(1, ks.size());

        Enumeration<String> aliasEnum = ks.aliases();
        if (!aliasEnum.hasMoreElements()) {
            Assertions.fail();
        }
        String alias = aliasEnum.nextElement();
        if (!ks.isKeyEntry(alias)) {
            Assertions.fail();
        }
        Key k = ks.getKey(alias, privateKeyPassword);
        Assertions.assertNotNull(k);
        if (!(k instanceof PrivateKey)) {
            Assertions.fail();
        }

        List<Certificate> certChain = Arrays.asList(ks.getCertificateChain(alias));
        List<Certificate> expectedCertChain = List.of(
            PemKeystoreTestUtils.getResourceCertificate("www.doesnotexist.org-" + algorithm + ".crt"),
            PemKeystoreTestUtils.getResourceCertificate("Test-Intermediate-CA-" + algorithm + ".crt"),
            PemKeystoreTestUtils.getResourceCertificate("Test-Root-CA-" + algorithm + ".crt"));
            Assertions.assertEquals(expectedCertChain, certChain);

        Assertions.assertTrue(PemKeystoreTestUtils.matching(certChain.get(0).getPublicKey(), (PrivateKey) k));
    }

    private static void testLoadRsaKeystoreChainAlias() throws Exception {
        File originalKeystore = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-keystore.pem");
        char[] password = "password".toCharArray();
        String expectedAlias = "CN=www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(originalKeystore, password);

        PrivateKey privateKey = (PrivateKey) ks.getKey(expectedAlias, null);
        Assertions.assertNotNull(privateKey);

        Certificate[] certChain = ks.getCertificateChain(expectedAlias);
        Assertions.assertNotNull(certChain);
    }

    private static void testStoreRsaKeystoreWithChain() throws Exception {
        File originalKeystore = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-keystore.pem");
        File savedKeystore = Files.createTempFile(originalKeystore.getName(), ".pem").toFile();
        char[] password = "password".toCharArray();

        KeyStore ks = loadKeyStore(originalKeystore, password);

        try (FileOutputStream fos = new FileOutputStream(savedKeystore)) {
            ks.store(fos, password);
        }

        Assertions.assertFilesEqualNormalizeLineBreaks(originalKeystore, savedKeystore);
        savedKeystore.delete();
    }

    private static KeyStore loadKeyStore(File keyStoreFile, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        ks.load(new FileInputStream(keyStoreFile), password);
        return ks;
    }

    private static void testCreateRsaKeystoreWithChain() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        ks.load(null, null);

        File certFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA.crt");
        File caCertFile = PemKeystoreTestUtils.getResourceFile("Test-Intermediate-CA-RSA.crt");
        File rootCertFile = PemKeystoreTestUtils.getResourceFile("Test-Root-CA-RSA.crt");
        File keyFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA.pem");
        String password = "password";
        String alias = "www.doesnotexist.org-RSA";

        PrivateKey privateKey = PemKeystoreTestUtils.readPrivateKey(keyFile, "RSA", password);
        X509Certificate certificate = PemKeystoreTestUtils.readCertificate(certFile);
        X509Certificate caCertificate = PemKeystoreTestUtils.readCertificate(caCertFile);
        X509Certificate rootCertificate = PemKeystoreTestUtils.readCertificate(rootCertFile);

        Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate };
        ks.setKeyEntry(alias, privateKey, null, certChain);

        File keystoreFile = Files.createTempFile("www.doesnotexist.org-RSA-keystore-created", ".pem").toFile();
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }

        File expectedKeystore = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-keystore-alias.pem");
        Assertions.assertFilesEqualNormalizeLineBreaks(expectedKeystore, keystoreFile);
        keystoreFile.delete();
    }

    private static void testCreateRsaKeystoreWithChainAndPW() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        ks.load(null, null);

        File certFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA.crt");
        File caCertFile = PemKeystoreTestUtils.getResourceFile("Test-Intermediate-CA-RSA.crt");
        File rootCertFile = PemKeystoreTestUtils.getResourceFile("Test-Root-CA-RSA.crt");
        File keyFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA.pem");
        String password = "password";
        String alias = "www.doesnotexist.org-RSA";

        PrivateKey privateKey = PemKeystoreTestUtils.readPrivateKey(keyFile, "RSA", password);
        X509Certificate certificate = PemKeystoreTestUtils.readCertificate(certFile);
        X509Certificate caCertificate = PemKeystoreTestUtils.readCertificate(caCertFile);
        X509Certificate rootCertificate = PemKeystoreTestUtils.readCertificate(rootCertFile);

        Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate };
        ks.setKeyEntry(alias, privateKey, password.toCharArray(), certChain);

        File keystoreFile =  Files.createTempFile("www.doesnotexist.org-RSA-keystore-created2", ".pem").toFile();
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }

        Assertions.assertEquals(1, ks.size());

        KeyStore ksReloaded = KeyStore.getInstance("pem", PROVIDER);
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            ksReloaded.load(fis, password.toCharArray());
        }
        Assertions.assertEquals(1, ksReloaded.size());
        Assertions.assertTrue(ksReloaded.containsAlias(alias));
        Assertions.assertTrue(ksReloaded.isKeyEntry(alias));

        Assertions.assertEquals(privateKey, ksReloaded.getKey(alias, password.toCharArray()));
        Assertions.assertArrayEquals(certChain, ksReloaded.getCertificateChain(alias));

        keystoreFile.delete();
    }

    private static void testCreateTrustKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        ks.load(null, null);

        List<File> caFileList = Arrays.asList(
            PemKeystoreTestUtils.getResourceFile("lets-encrypt-ca-R3.crt"),
            PemKeystoreTestUtils.getResourceFile("lets-encrypt-root-ISRG-Root-X1.crt"),
            PemKeystoreTestUtils.getResourceFile("Test-Intermediate-CA-RSA.crt"),
            PemKeystoreTestUtils.getResourceFile("Test-Root-CA-RSA.crt"));

        for (File certFile : caFileList) {
            X509Certificate certificate = PemKeystoreTestUtils.readCertificate(certFile);
            String alias = certFile.getName().replaceFirst("[.][^.]+$", "");
            ks.setCertificateEntry(alias, certificate);
        }

        File keystoreFile = Files.createTempFile("ca-truststore-created", ".pem").toFile();
        String password = "password";
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }

        File expectedKeystore = PemKeystoreTestUtils.getResourceFile("ca-truststore.pem");
        Assertions.assertFilesEqualNormalizeLineBreaks(expectedKeystore, keystoreFile);

        keystoreFile.delete();
    }

    private static void testDeleteKeyAndChain() throws Exception {
        File originalKeystore = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-keystore.pem");
        char[] password = "password".toCharArray();
        String alias = "CN=www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(originalKeystore, password);

        ks.deleteEntry(alias);

        Assertions.assertFalse(ks.containsAlias(alias));
    }

    private static void testCreationDate() throws Exception {
        File originalKeystore = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-keystore.pem");
        char[] password = "password".toCharArray();
        String alias = "CN=www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(originalKeystore, password);

        Date creationDate = ks.getCreationDate(alias);

        Assertions.assertNotNull(creationDate);
    }

    private static void testGetCertificateAlias() throws Exception {
        File originalKeystore = PemKeystoreTestUtils.getResourceFile("truststore.pem");
        char[] password = "password".toCharArray();

        KeyStore ks = loadKeyStore(originalKeystore, password);

        boolean checked = false;
        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String expectedAlias = aliasEnum.nextElement();
            if (ks.isCertificateEntry(expectedAlias)) {
                Certificate c = ks.getCertificate(expectedAlias);
                String a = ks.getCertificateAlias(c);
                Assertions.assertEquals(expectedAlias, a);
                // to ensure this loop checked at least one entry
                checked = true;
            }
        }
        Assertions.assertTrue(checked);

        Assertions.assertNull(ks.getCertificateAlias(null));
    }

    private static void testGetCertificateChainAlias() throws Exception {
        File originalKeystore = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-keystore.pem");
        char[] password = "password".toCharArray();
        String alias = "CN=www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(originalKeystore, password);

        X509Certificate eeCert = PemKeystoreTestUtils.getResourceCertificate("www.doesnotexist.org-RSA.crt");
        String eeCertAlias = ks.getCertificateAlias(eeCert);

        Assertions.assertEquals(alias, eeCertAlias);
    }

    private static void testGetCertificateAliasEmptyChain() throws Exception {
        checkPrivateKey("rsa-2048.pem", "pem", null, RSAPrivateKey.class);
    }

    private static void testReadAlias() throws Exception {
        File keystore = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-keystore-alias.pem");
        char[] password = "password".toCharArray();
        String alias = "www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(keystore, password);

        Assertions.assertTrue(ks.isKeyEntry(alias));
        Key pk = ks.getKey(alias, password);
        Assertions.assertNotNull(pk);

        Certificate[] cc = ks.getCertificateChain(alias);
        Assertions.assertNotNull(cc);
        Assertions.assertEquals(3, cc.length);
    }

    private static void testStorePemTruststore() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        ks.load(null, null);

        ks.setCertificateEntry("github.com", PemKeystoreTestUtils.getResourceCertificate("github.com.crt"));
        ks.setCertificateEntry("google.com", PemKeystoreTestUtils.getResourceCertificate("google.com.crt"));
        ks.setCertificateEntry("microsoft.com", PemKeystoreTestUtils.getResourceCertificate("microsoft.com.crt"));
        ks.setCertificateEntry("orf.at", PemKeystoreTestUtils.getResourceCertificate("orf.at.crt"));

        File truststoreFile =  Files.createTempFile("truststore-alias-created", ".pem").toFile();
        try (FileOutputStream fos = new FileOutputStream(truststoreFile)) {
            ks.store(fos, null);
        }

        File expectedTruststoreFile = PemKeystoreTestUtils.getResourceFile("truststore-alias.pem");
        Assertions.assertFilesEqualNormalizeLineBreaks(expectedTruststoreFile, truststoreFile);

        truststoreFile.delete();
    }

    private static byte[] readPemData(File pemFile) throws Exception {
        String pemKey = Files.readAllLines(pemFile.toPath()).stream().filter(s -> !s.startsWith("-----"))
        .collect(Collectors.joining(""));
        return Base64.getDecoder().decode(pemKey);
    }

    private static void testStoreEncryptedRSAKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        ks.load(null, null);

        File certFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA.crt");
        File caCertFile = PemKeystoreTestUtils.getResourceFile("Test-Intermediate-CA-RSA.crt");
        File rootCertFile = PemKeystoreTestUtils.getResourceFile("Test-Root-CA-RSA.crt");
        File keyFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-enc.pem");
        String password = "password";
        String alias = "www.doesnotexist.org-RSA";

        byte[] encryptedPrivateKey = readPemData(keyFile);
        X509Certificate certificate = PemKeystoreTestUtils.readCertificate(certFile);
        X509Certificate caCertificate = PemKeystoreTestUtils.readCertificate(caCertFile);
        X509Certificate rootCertificate = PemKeystoreTestUtils.readCertificate(rootCertFile);

        Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate };

        ks.setKeyEntry(alias, encryptedPrivateKey, certChain);

        File keystoreFile =  Files.createTempFile("www.doesnotexist.org-RSA-enc-keystore-created", ".pem").toFile();
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }

        File expectedKeystore = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-RSA-enc-keystore.pem");
        Assertions.assertFilesEqualNormalizeLineBreaks(expectedKeystore, keystoreFile);

        keystoreFile.delete();
    }

    private static void loadMozillaRootStore4TLS() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);

        // file from
        // "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"
        File mozillaTruststoreFile = PemKeystoreTestUtils.getResourceFile("IncludedRootsPEM.txt");
        try (FileInputStream is = new FileInputStream(mozillaTruststoreFile)) {
            ks.load(is, null);
        }
        Assertions.assertTrue(ks.size() > 0);

        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            if (ks.isCertificateEntry(alias)) {
                Certificate c = ks.getCertificate(alias);
                Assertions.assertNotNull(c);
                if (c instanceof X509Certificate) {
                    X509Certificate xc = (X509Certificate) c;
                    String subjectDN = xc.getSubjectX500Principal().getName();
                    Assertions.assertTrue(alias.startsWith(subjectDN));
                } else {
                    Assertions.fail("invalid certificate entry not of type X509Certificate, alias: " + alias);
                }
            } else {
                Assertions.fail("invalid keystore entry not of type trusted certificate, alias: " + alias);
            }
        }
    }

    private static void testLoadPemTruststoreAliasExplanatory() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        Assertions.assertNotNull(ks);

        ks.load(PemKeystoreTestUtils.getResource("truststore-alias-explanatory.pem"), null);
        Assertions.assertEquals(4, ks.size());

        Assertions.assertEquals(PemKeystoreTestUtils.getResourceCertificate("github.com.crt"), ks.getCertificate("github.com"));
        Assertions.assertEquals(PemKeystoreTestUtils.getResourceCertificate("google.com.crt"), ks.getCertificate("google.com"));
        Assertions.assertEquals(PemKeystoreTestUtils.getResourceCertificate("microsoft.com.crt"), ks.getCertificate("microsoft.com"));
        Assertions.assertEquals(PemKeystoreTestUtils.getResourceCertificate("orf.at.crt"), ks.getCertificate("orf.at"));
    }

    private static void testGetViaAlias() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        File keystoreFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-EC-keystore-alias.pem");
        ks.load(new FileInputStream(keystoreFile), null);

        Assertions.assertNull(ks.getKey("unknown-alias", null));
        Assertions.assertNull(ks.getCertificate("unknown-alias"));
        Assertions.assertNull(ks.getCertificateChain("unknown-alias"));

        Assertions.assertNotNull(ks.getKey("www.doesnotexist.org-EC", null));
        Assertions.assertNotNull(ks.getCertificateChain("www.doesnotexist.org-EC"));
        Assertions.assertNotNull(ks.getCertificate("www.doesnotexist.org-EC"));
        Assertions.assertEquals(PemKeystoreTestUtils.getResourceCertificate("www.doesnotexist.org-EC.crt"), ks.getCertificate("www.doesnotexist.org-EC"));
    }

    private static void testLoadEnc() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        File keystoreFile = PemKeystoreTestUtils.getResourceFile("www.doesnotexist.org-EC-enc.pem");
        ks.load(new FileInputStream(keystoreFile), null);

        Assertions.assertNull(ks.getKey("unknown-alias", null));
        Assertions.assertNull(ks.getCertificate("unknown-alias"));
        Assertions.assertNull(ks.getCertificateChain("unknown-alias"));

        try {
            ks.getKey("private-key", null);
            Assertions.fail("getting an encrypted key entry without password must fail");
        } catch (NoSuchAlgorithmException e) {
            // expected
        }
    }

    private static void testUnsupportedKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        ks.load(null, null);

        try {
            ks.setKeyEntry("alias", null, null, null);
            Assertions.fail("setting a null entry must fail");
        } catch (KeyStoreException e) {
            // expected
        }

        PublicKey publicKey1a = PemKeystoreTestUtils.getResourceCertificate("www.doesnotexist.org-RSA.crt").getPublicKey();
        try {
            ks.setKeyEntry("alias", publicKey1a, null, null);
            Assertions.fail("setting a public-key entry must fail");
        } catch (KeyStoreException e) {
            // expected
        }
    }

    private static void testUnsupportedCertificate() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", PROVIDER);
        ks.load(null, null);

        try {
            ks.setCertificateEntry("alias", null);
            Assertions.fail("setting a null certificate entry must fail");
        } catch (KeyStoreException e) {
            // expected
        }
    }

}