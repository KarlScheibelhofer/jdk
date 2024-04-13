/*
 * Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package java.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.Pem;
import sun.security.x509.AlgorithmId;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.Pem;
import sun.security.x509.AlgorithmId;

/**
 * PEMEncoder is an immutable Privacy-Enhanced Mail (PEM) encoding class.
 * PEM is a textual encoding used for storing and transferring security
 * objects, such as asymmetric keys, certificates, and certificate revocation
 * lists (CRL). Defined in RFC 1421 and RFC 7468, PEM consists of a
 * Base64-formatted binary encoding surrounded by a type identifying header
 * and footer.
 *
 * <p> Encoding is limited to classes that implement {@link SecurityObject},
 * which include classes and interfaces like
 * {@link PublicKey}, {@link PrivateKey}, {@link KeyPair},
 * {@link EncryptedPrivateKeyInfo}, {@link Certificate}, and {@link CRL}.
 *
 * <p> Encrypted private key PEM data can be built by calling the encode methods
 * on a PEMEncoder instance returned by {@link #withEncryption(char[])} or
 * by passing an {@link EncryptedPrivateKeyInfo} object into the encode methods.
 *
 * <p> PKCS8 v2.0 allows OneAsymmetric encoding, which is a private and public
 * key in the same PEM.  This is supported by using the {@link KeyPair} class
 * with the encode methods.
 *
 * <br>
 * @apiNote
 * Here is an example of encoding a PrivateKey object:
 * <pre>{@code
 *     PEMEncoder pe = PEMEncoder.of();
 *     byte[] pemData = pe.encode(privKey);
 * }</pre>
 *
 */
final public class PEMEncoder implements Encoder<SecurityObject> {

    // Singleton instance of PEMEncoder
    final private static PEMEncoder PEM_ENCODER = new PEMEncoder(null);

    // If non-null, encoder is configured for encryption
    private Cipher cipher;

    /**
     * Instantiate a new PEMEncoder for Encrypted Private Keys.
     *
     * @param c the cipher object that will be used for encryption
     */
    private PEMEncoder(Cipher c) {
        cipher = c;
    }

    /**
     * Returns a instance of PEMEncoder.
     *
     * @return PEMEncoder instance
     */
    static public PEMEncoder of() {
        return PEM_ENCODER;
    }

    /**
     * Construct a String-based encoding based off the {@code keyType} given.
     *
     * @param keyType the key type
     * @param encoded the encoded
     * @return the string
     */
    private byte[] pemEncoded(Pem.Type keyType, byte[] encoded) {
    private byte[] pemEncoded(Pem.Type keyType, byte[] encoded) {
        ByteArrayOutputStream os = new ByteArrayOutputStream(1024);
        os.writeBytes(keyType.getHeader());
        os.writeBytes(Pem.LINESEPARATOR);
        os.writeBytes(Base64.getMimeEncoder(64, Pem.LINESEPARATOR).encode(encoded));        
        os.writeBytes(keyType.getHeader());
        os.writeBytes(Pem.LINESEPARATOR);
        os.writeBytes(Base64.getMimeEncoder(64, Pem.LINESEPARATOR).encode(encoded));        
        os.writeBytes(Pem.LINESEPARATOR);
        os.writeBytes(keyType.getFooter());

        os.writeBytes(keyType.getFooter());

        return os.toByteArray();
    }

    /**
     * Encoded a given SecurityObject and return the PEM encoding in a String
     *
     * @param so a cryptographic object to be PEM encoded that implements
     *           SecurityObject.
     * @return PEM encoding in a String
     * @throws IOException on any error with the object or the encoding process.
     * An exception is thrown when PEMEncoder is configured for encryption while
     * encoding a SecurityObject that does not support encryption.
     * @see #withEncryption(char[])
     */
    public String encodeToString(SecurityObject so) throws IOException {
            return new String(encode(so), StandardCharsets.US_ASCII);
            return new String(encode(so), StandardCharsets.US_ASCII);
    }

    /**
     * Encoded a given SecurityObject into PEM.
     *
     * @param so the object that implements SecurityObject.
     * @return a PEM encoded string of the given SecurityObject.
     * @throws IOException on any error with the object or the encoding process.
     * An exception is thrown when PEMEncoder is configured for encryption while
     * encoding a SecurityObject that does not support encryption.
     * @see #withEncryption(char[])
     */
    @Override
    public byte[] encode(SecurityObject so) throws IOException {
        Objects.requireNonNull(so);
        return switch (so) {
            case PublicKey pu -> build(null, pu.getEncoded());
            case PrivateKey pr -> build(pr.getEncoded(), null);
            case KeyPair kp -> {
                if (kp.getPublic() == null) {
                    throw new IOException("KeyPair does not contain PublicKey.");
                }

                if (kp.getPrivate() == null) {
                    throw new IOException("KeyPair does not contain PrivateKey.");
                }
                yield build(kp.getPrivate().getEncoded(),
                    kp.getPublic().getEncoded());
            }
            case X509EncodedKeySpec x -> build(null, x.getEncoded());
            case PKCS8EncodedKeySpec p -> build(p.getEncoded(), null);
            case EncryptedPrivateKeyInfo e -> {
                if (cipher != null) {
                    throw new IOException("encrypt was incorrectly used");
                }
                yield pemEncoded(Pem.Type.ENCRYPTED_PRIVATE, e.getEncoded());
                yield pemEncoded(Pem.Type.ENCRYPTED_PRIVATE, e.getEncoded());
            }
            case Certificate c -> {
                byte[] encodedObject;
                byte[] encodedObject;
                try {
                    encodedObject = c.getEncoded();
                    encodedObject = c.getEncoded();
                } catch (CertificateException e) {
                    throw new IOException(e);
                }
                yield pemEncoded(Pem.Type.CERTIFICATE, encodedObject);
                yield pemEncoded(Pem.Type.CERTIFICATE, encodedObject);
            }
            case X509CRL crl -> {
                byte[] encodedObject;
            case X509CRL crl -> {
                byte[] encodedObject;
                try {
                    encodedObject = crl.getEncoded();
                    encodedObject = crl.getEncoded();
                } catch (CRLException e) {
                    throw new IOException(e);
                }
                yield pemEncoded(Pem.Type.CRL, encodedObject);
                yield pemEncoded(Pem.Type.CRL, encodedObject);
            }
            default -> throw new IOException("PEM does not support " +
                so.getClass().getCanonicalName());
        };
    }

    /**
     * Returns a new immutable PEMEncoder instance configured to the default
     * encrypt algorithm and a given password.
     *
     * <p> Only {@link PrivateKey} will be encrypted with this newly configured
     * instance.  Other {@link SecurityObject} classes that do not support
     * encrypted PEM will cause encode() to throw an IOException.
     *
     * <p> Default algorithm defined by Security Property {@code
     * jdk.epkcs8.defaultAlgorithm}.  To configure all the encryption options
     * see {@link EncryptedPrivateKeyInfo#encryptKey(PrivateKey, char[], String,
     * AlgorithmParameterSpec, Provider)} and use the returned object with
     * {@link #encode(SecurityObject)}.
     *
     * @param password the password
     * @return a new PEMEncoder
     * @throws IOException on any encryption errors.
     */
    public PEMEncoder withEncryption(char[] password) throws IOException {
        char[] pwd = password.clone();
        Objects.requireNonNull(pwd);

        // PBEKeySpec clones the password array
        PBEKeySpec spec = new PBEKeySpec(pwd);
        Arrays.fill(pwd, (char)0x0);

        try {
            SecretKeyFactory factory;
            factory = SecretKeyFactory.getInstance(Pem.DEFAULT_ALGO);
            Cipher c = Cipher.getInstance(Pem.DEFAULT_ALGO);
            c.init(Cipher.ENCRYPT_MODE, factory.generateSecret(spec));
            return new PEMEncoder(c);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Security property " +
                "\"jdk.epkcs8.defaultAlgorithm\" may not specify a " +
                "valid algorithm.", e);
        } catch (Exception e) {
            throw new IOException(e);
        }

    }

    /**
     * Build PEM encoding.
     */
    private byte[] build(byte[] privateBytes, byte[] publicBytes)
        throws IOException {
        DerOutputStream out = new DerOutputStream();
        byte[] encoded;

        // Encrypted PKCS8
        if (cipher != null) {
            if (privateBytes == null || publicBytes != null) {
                throw new IOException("Can only encrypt a PrivateKey.");
            }
            try {
                new AlgorithmId(Pem.getPBEID(Pem.DEFAULT_ALGO),
                    cipher.getParameters()).encode(out);
                out.putOctetString(cipher.doFinal(privateBytes));
                encoded = DerValue.wrap(DerValue.tag_Sequence, out).
                    toByteArray();
            } catch (Exception e) {
                throw new IOException(e);
            }
            return pemEncoded(Pem.Type.ENCRYPTED_PRIVATE, encoded);
            return pemEncoded(Pem.Type.ENCRYPTED_PRIVATE, encoded);
        }

        // X509 only
        if (publicBytes != null && privateBytes == null) {
            return pemEncoded(Pem.Type.PUBLIC, publicBytes);
            return pemEncoded(Pem.Type.PUBLIC, publicBytes);
        }
        // PKCS8 only
        if (publicBytes == null && privateBytes != null) {
            return pemEncoded(Pem.Type.PRIVATE, privateBytes);
            return pemEncoded(Pem.Type.PRIVATE, privateBytes);
        }
        // OAS
        return pemEncoded(Pem.Type.PRIVATE, PKCS8Key.getEncoded(publicBytes,
        return pemEncoded(Pem.Type.PRIVATE, PKCS8Key.getEncoded(publicBytes,
            privateBytes));
    }
}
