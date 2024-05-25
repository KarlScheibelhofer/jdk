package sun.security.pem;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import sun.security.x509.AlgorithmId;
import sun.security.util.DerValue;
import sun.security.util.DerInputStream;

/**
 * Internal support class for reading and writing PEM format keys and certificates.
 */
abstract class Pem {

    private Pem() {
        // empty
    }

    static abstract class Entry {
        static enum Type {
            privateKey, certificate, encryptedPrivateKey, unknown
        }

        Type type;
        byte[] encoding;
        String alias;

        Entry(Type type, String alias) {
            this.type = type;
            this.alias = alias;
        }

        void initFromEncoding(byte[] encoding) throws IOException {
            this.encoding = encoding;
        }

    }

    static class PrivateKeyEntry extends Entry {
        PrivateKey privateKey;

        PrivateKeyEntry(String alias) {
            super(Type.privateKey, alias);
        }

        PrivateKeyEntry(Type type, String alias) {
            super(type, alias);
        }

        PrivateKeyEntry(String alias, PrivateKey privateKey) {
            this(alias);
            this.privateKey = privateKey;
            this.encoding = privateKey.getEncoded();
        }

        @Override
        void initFromEncoding(byte[] encoding) throws IOException {
            super.initFromEncoding(encoding);
            try {
                PKCS8EncodedKeySpec spec = pkcs8EncodingToSpec(encoding);
                KeyFactory kf = KeyFactory.getInstance(spec.getAlgorithm());
                this.privateKey = kf.generatePrivate(spec);
            } catch (Exception e) {
                throw new IOException("failed decoding private key entry", e);
            }
        }

        // taken from javax.crypto.EncryptedPrivateKeyInfo, TODO: consider refactoring there to make it accessible
        private static void checkTag(DerValue val, byte tag, String valName) throws IOException {
            if (val.getTag() != tag) {
                throw new IOException("invalid key encoding - wrong tag for " + valName);
            }
        }

        // taken from javax.crypto.EncryptedPrivateKeyInfo, TODO: consider refactoring there to make it accessible
        @SuppressWarnings("fallthrough")
        private static PKCS8EncodedKeySpec pkcs8EncodingToSpec(byte[] encodedKey) throws IOException {
            DerInputStream in = new DerInputStream(encodedKey);
            DerValue[] values = in.getSequence(3);

            switch (values.length) {
            case 4:
                checkTag(values[3], DerValue.TAG_CONTEXT, "attributes");
                /* fall through */
            case 3:
                checkTag(values[0], DerValue.tag_Integer, "version");
                String keyAlg = AlgorithmId.parse(values[1]).getName();
                checkTag(values[2], DerValue.tag_OctetString, "privateKey");
                return new PKCS8EncodedKeySpec(encodedKey, keyAlg);
            default:
                throw new IOException("invalid key encoding");
            }
        }

    }

    static class EncryptedPrivateKeyEntry extends PrivateKeyEntry {
        EncryptedPrivateKeyInfo encryptedPrivateKey;

        EncryptedPrivateKeyEntry(String alias) {
            super(Type.encryptedPrivateKey, alias);
        }

        public EncryptedPrivateKeyEntry(String alias, PrivateKey key, char[] password) {
            super(Type.encryptedPrivateKey, alias);
            this.privateKey = key;
            encryptPrivateKey(password);
        }

        public EncryptedPrivateKeyEntry(String alias, EncryptedPrivateKeyInfo encryptedPrivateKey) {
            super(Type.encryptedPrivateKey, alias);
            this.encryptedPrivateKey = encryptedPrivateKey;
            try {
                this.encoding = encryptedPrivateKey.getEncoded();
            } catch (IOException e) {
                throw new PemKeystoreException("failed encoding encrypted private key", e);
            }            
        }

        @Override
        void initFromEncoding(byte[] encoding) throws IOException {
            this.encoding = encoding;
            try {
                this.encryptedPrivateKey = new EncryptedPrivateKeyInfo(encoding);
            } catch (IOException e) {
                throw new IOException("failed decoding encrypted private key", e);
            }
        }

        void decryptPrivateKey(char[] password) throws NoSuchAlgorithmException {
            try {
                this.privateKey = this.encryptedPrivateKey.getKey(password);
            } catch (InvalidKeyException e) {
                throw new PemKeystoreException("error decrypting private key", e);
            }
        }

        void encryptPrivateKey(char[] password) {
            try {
                PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
                String pbes2Name = "PBEWithHmacSHA256AndAES_256";
                SecretKeyFactory skf = SecretKeyFactory.getInstance(pbes2Name);
                Key pbeKey = skf.generateSecret(pbeKeySpec);

                Cipher cipher = Cipher.getInstance(pbes2Name);

                byte[] salt = new byte[8];
                SecureRandom.getInstance("NativePRNGNonBlocking").nextBytes(salt);
                int iterations = 2048;
                byte[] iv = new byte[16];
                SecureRandom.getInstance("NativePRNGNonBlocking").nextBytes(iv);
                IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
                PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterations, ivParamSpec);

                cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

                KeyFactory kf = KeyFactory.getInstance(this.privateKey.getAlgorithm());
                PKCS8EncodedKeySpec pkcs8keyspec = kf.getKeySpec(this.privateKey, PKCS8EncodedKeySpec.class);
                byte[] encodedPlainPrivateKey = pkcs8keyspec.getEncoded();

                byte[] encryptedData = cipher.doFinal(encodedPlainPrivateKey);

                AlgorithmParameters pbeAlgParams = AlgorithmParameters.getInstance("PBES2", "SUN");
                pbeAlgParams.init(pbeParamSpec);
                // TODO: pbeAlgParams is encoded incomplete
                // compare
                // base64 --decode rsa-2048-aes128.b64| dumpasn1 -
                // base64 --decode www.doesnotexist.org-RSA-keystore-created.b64| dumpasn1 -
                this.encryptedPrivateKey = new EncryptedPrivateKeyInfo(pbeAlgParams, encryptedData);
                this.encoding = this.encryptedPrivateKey.getEncoded();
            } catch (GeneralSecurityException | IOException e) {
                throw new PemKeystoreException("error encrypting private key", e);
            }
        }
    }

    static class CertificateEntry extends Entry {
        X509Certificate certificate;

        CertificateEntry(String alias) {
            super(Type.certificate, alias);
        }

        CertificateEntry(String alias, X509Certificate certificate) {
            this(alias);
            this.certificate = certificate;
            try {
                this.encoding = certificate.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new PemKeystoreException("failed encoding certificate", e);
            }
        }

        @Override
        void initFromEncoding(byte[] encoding) throws IOException {
            super.initFromEncoding(encoding);
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                this.certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoding));
            } catch (Exception e) {
                throw new IOException("failed decoding certificate", e);
            }
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((certificate == null) ? 0 : certificate.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            CertificateEntry other = (CertificateEntry) obj;
            if (certificate == null) {
                if (other.certificate != null)
                    return false;
            } else if (!certificate.equals(other.certificate))
                return false;
            return true;
        }

    }

    static class UnknownEntry extends Entry {
        String pemBeginLine;
        String pemEndLine;

        UnknownEntry(String alias, String pemBeginLine, String pemEndLine) {
            super(Type.unknown, alias);
            this.pemBeginLine = pemBeginLine;
            this.pemEndLine = pemEndLine;
        }
    }

    final static String BEGIN = "-----BEGIN";
    final static String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    final static String END_CERTIFICATE = "-----END CERTIFICATE-----";
    final static String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    final static String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    final static String BEGIN_ENCRYPTED_PRIVATE_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    final static String END_ENCRYPTED_PRIVATE_KEY = "-----END ENCRYPTED PRIVATE KEY-----";
    final static String END = "-----END";

}
