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

import sun.security.pkcs.PKCS8Key;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.util.Pem;

import javax.crypto.EncryptedPrivateKeyInfo;
import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * <p>PEM is a textual encoding used for storing and transferring security
 * objects, such as asymmetric keys, certificates, and certificate revocation
 * lists (CRL). Defined in RFC 1421 and RFC 7468, PEM consists of a
 * Base64-formatted binary encoding surrounded by a type identifying header
 * and footer.
 *
 * <p>PEMDecoder is an immutable Privacy-Enhanced Mail (PEM) decoding class.
 * Decoding will return a {@link SecurityObject} or class that implements
 * {@link SecurityObject} depending on the decode method used.
 *
 * <p>There are four methods to complete the decoding process. They each return
 * a {@link SecurityObject} for which the caller can use instanceof or switch
 * when processing the result. If the developer knows the class type being
 * decoded, the two {@code decode} methods that take a {@code Class<S>}
 * argument, can be used to specify the returned object class. If the class
 * does not match the PEM type, an IOException is thrown.
 *
 * When passing input data into {@code decode}, the application is responsible
 * for processing input data ahead of the PEM text. All data before the PEM
 * header will be ignored.
 *
 * <p>A new immutable PEMDecoder instance is returned by
 * {@linkplain #withFactory} and/or {@linkplain #withDecryption}.  Configuring
 * an instance for decryption does not prevent decoding with unencrypted PEM.
 * Any encrypted PEM that does not use the configured password will cause an
 * exception. A decoder instance not configured with decryption will return an
 * {@link EncryptedPrivateKeyInfo} with encrypted PEM.  EncryptedPrivateKeyInfo
 * methods must be used to retrieve the {@link PrivateKey}.
 *
 */

final public class PEMDecoder implements Decoder<SecurityObject> {
    final private Provider factory;
    final private char[] password;

    // Singleton instance for PEMDecoder
    final private static PEMDecoder PEM_DECODER = new PEMDecoder(null, null);

    /**
     * Creates a immutable instance with a specific KeyFactory and/or password.
     * @param withFactory KeyFactory provider
     * @param withPassword char[] password for EncryptedPrivateKeyInfo
     *                    decryption
     */
    private PEMDecoder(Provider withFactory, char[] withPassword) {
        super();
        factory = withFactory;
        password = withPassword;
    }

    /**
     * Returns an instance of PEMDecoder.  This instance may be repeatedly used
     * to decode different PEM text.
     *
     * @return returns a PEMDecoder
     */
    public static PEMDecoder of() {
        return PEM_DECODER;
    }

    /**
     * After the header, footer, and base64 have been separated, identify the
     * header and footer and proceed with decoding the base64 for the
     * appropriate type.
     */
    private SecurityObject decode(Pem pem) throws IOException {
        Pem.Type pemType = pem.getType();
        if (pemType.equals(Pem.Type.UNKNOWN))  {
            throw new IOException("Unsupported PEM header/footer");
        }

        if (password != null) {
            if (pemType != Pem.Type.ENCRYPTED_PRIVATE) {
                throw new IOException("Decoder configured only for encrypted PEM.");
            }
        }

        Base64.Decoder decoder = Base64.getMimeDecoder();
        byte[] data = pem.getData();

        return switch (pemType) {
            case PUBLIC -> {
                X509EncodedKeySpec spec =
                    new X509EncodedKeySpec(decoder.decode(data));
                try {
                    yield ((KeyFactory) getFactory(pemType,
                        spec.getAlgorithm())).generatePublic(spec);
                } catch (Exception e) {
                    throw new IOException(e);
                }
            }
            case PRIVATE -> {
                try {
                    PKCS8Key p8key = new PKCS8Key(decoder.decode(data));
                    PrivateKey priKey;
                    KeyFactory kf = (KeyFactory)
                        getFactory(pemType, p8key.getAlgorithm());
                    priKey = kf.generatePrivate(
                        new PKCS8EncodedKeySpec(p8key.getEncoded(),
                            p8key.getAlgorithm()));
                    // If there is a public key, it's an OAS.
                    if (p8key.getPubKeyEncoded() != null) {
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(
                            p8key.getPubKeyEncoded(), p8key.getAlgorithm());
                        yield new KeyPair(((KeyFactory)
                                getFactory(pemType, p8key.getAlgorithm()))
                                .generatePublic(spec),
                            priKey);
                    }
                    yield priKey;
                } catch (Exception e) {
                    throw new IOException(e);
                }
            }
            case ENCRYPTED_PRIVATE -> {
                if (password == null) {
                    yield new EncryptedPrivateKeyInfo(decoder.decode(data));
                }
                yield new EncryptedPrivateKeyInfo(decoder.decode(data)).
                    getKey(password);
            }
            case CERTIFICATE -> {
                try {
                    CertificateFactory cf =
                        (CertificateFactory) getFactory(pemType, "X509");
                    yield cf.generateCertificate(
                        new ByteArrayInputStream(decoder.decode(data)));
                } catch (CertificateException e) {
                    throw new IOException(e);
                }
            }
            case CRL -> {
                try {
                    CertificateFactory cf =
                        (CertificateFactory) getFactory(pemType, "X509");
                    yield cf.generateCRL(
                        new ByteArrayInputStream(decoder.decode(data)));

                } catch (Exception e) {
                    throw new IOException(e);
                }
            }
            case PKCS1 -> {
                try {
                    KeyFactory kf = (KeyFactory)
                        getFactory(pemType, "RSA");
                    yield kf.generatePrivate(
                        RSAPrivateCrtKeyImpl.getKeySpec(decoder.decode(data)));
                } catch (Exception e) {
                    throw new IOException(e);
                }

            }
            default -> throw new IOException("Unsupported type or not " +
                "properly formatted PEM");
        };
    }

    /**
     * Decodes and returns {@code SecurityObject} from the given string.
     *
     * @param str PEM data in a String.
     * @return an SecurityObject generated from the PEM data.
     * @throws IOException on an error in decoding or if the PEM is unsupported.
     */
    @Override
    public SecurityObject decode(String str) throws IOException {
        Objects.requireNonNull(str);
        return decode(new ByteArrayInputStream(str.getBytes()));
    }

    /**
     * Decodes and returns a {@code SecurityObject} from the given
     * {@code InputStream}.
     * The method will read the {@code InputStream} until PEM data is
     * found or until the end of the stream.  Non-PEM data in the
     * {@code InputStream} before the PEM header will be ignored by the decoder.
     *
     * @param is InputStream containing PEM data.
     * @return an SecurityObject generated from the PEM data.
     * @throws IOException on an error in decoding or if the PEM is unsupported.
     */
    @Override
    public SecurityObject decode(InputStream is) throws IOException {
        Objects.requireNonNull(is);
        Pem pem = Pem.readPEM(is);
        if (pem == null) {
            throw new IOException("No PEM data found.");
        }
        return decode(pem);
    }

    /**
     * Decodes and returns the specified class for the given PEM string.  The
     * class must extend {@code SecurityObject} and be the appropriate class for
     * the PEM type.
     *
     * <p>With the {@code tClass} argument, the returned object may be cast to a
     * subclass or converted to a different return class, if
     * appropriate for that PEM data.  Using EC public key PEM as an example,
     * {@code tClass} may be set to {@code PublicKey.class},
     * {@code ECPublicKey}, or a {@code X509EncodedKeySpec}.  {@code PublicKey}
     * is useful for algorithm-agnostic methods, {@code ECPublicKey} for
     * algorithm-specific operations, or {@code X509EncodedKeySpec} if the
     * X.509 binary encoding is desired instead of a Key object.  An IOException
     * will be thrown if the class is incorrect for the given PEM data.
     *
     * @param <S> Class type parameter that extends {@code SecurityObject}
     * @param string the String containing PEM data.
     * @param tClass  the returned object class that implementing
     * {@code SecurityObject}.
     * @return The SecurityObject typecast to tClass.
     * @throws IOException on an error in decoding, unsupported PEM, or
     * error casting to tClass.
     */
    @Override
    public <S extends SecurityObject> S decode(String string,
        Class<S> tClass) throws IOException {
        Objects.requireNonNull(string);

        return decode(new ByteArrayInputStream(string.getBytes()), tClass);
    }

    /**
     * Decodes and returns the specified class for the given PEM stream.  The
     * class must extend {@code SecurityObject} and be an appropriate class for
     * the PEM type.
     *
     * <p>See {@link PEMDecoder#decode(String, Class)} for details about {@code tClass}.
     * <br>See {@link PEMDecoder#decode(InputStream)} for details on using an {@code InputStream}.
     *
     * @param <S> Class type parameter that extends {@code SecurityObject}
     * @param is an InputStream containing PEM data.
     * @param tClass the returned object class that implementing
     *   {@code SecurityObject}.
     * @return  tClass.
     * @throws IOException on an error in decoding, unsupported PEM, or
     * error casting to tClass.
     */
    @Override
    @SuppressWarnings("unchecked")  // (Class<KeySpec>) tClass
    public <S extends SecurityObject> S decode(InputStream is,
        Class<S> tClass) throws IOException {
        Objects.requireNonNull(is);
        Objects.requireNonNull(tClass);
        Pem pem = Pem.readPEM(is);
        if (pem == null) {
            throw new IOException("No PEM data found.");
        }

        SecurityObject so = decode(pem);

        /*
         * KeySpec use getKeySpec after the Key has been generated.  Even though
         * returning a binary encoding after the Base64 decoding is ok when the
         * user wants PKCS8EncodedKeySpec, generating the key verifies the
         * binary encoding and allows the KeyFactory to use the provider's
         * KeySpec()
         */
        if ((KeySpec.class).isAssignableFrom(tClass)) {
            if (so instanceof KeyPair kp) {
                // Since a public key is possible in an OAS PEM
                if ((X509EncodedKeySpec.class).isAssignableFrom(tClass)) {
                    so = kp.getPublic();
                } else {
                    // Default assumption is a private key from OAS PEM.
                    so = kp.getPrivate();
                }
            }
            if (so instanceof Key key) {
                try {
                    // unchecked suppressed as we know tClass comes from KeySpec
                    // KeyType not relevant here.  We just want KeyFactory
                    so = ((KeyFactory) getFactory(Pem.Type.PRIVATE,
                        key.getAlgorithm())).
                        getKeySpec(key, (Class<KeySpec>) tClass);
                } catch (InvalidKeySpecException e) {
                    throw new IOException(e);
                }
            }
        }

        /*
         * If the object is a KeyPair, check if the tClass is set to private
         * or public key.  Because PKCS8v2 can be a KeyPair, it is possible for
         * someone to assume all their PEM private keys are only PrivateKey and
         * not KeyPair.
         */
        if (so instanceof KeyPair kp) {
            if ((PrivateKey.class).isAssignableFrom(tClass)) {
                so = kp.getPrivate();
            }
            if ((PublicKey.class).isAssignableFrom(tClass)) {
                so = kp.getPublic();
            }
        }

        try {
            return tClass.cast(so);
        } catch (ClassCastException e) {
            throw new IOException(e);
        }
    }

    // Convenience method to avoid provider getInstance checks clutter
    private Object getFactory(Pem.Type type, String algorithm)
        throws IOException {
        try {
            if (factory == null) {
                return switch (type) {
                    case PUBLIC, PRIVATE, PKCS1 ->
                        KeyFactory.getInstance(algorithm);
                    case CERTIFICATE, CRL ->
                        CertificateFactory.getInstance(algorithm);
                    default -> null;  // no possible
                };
            } else {
                return switch (type) {
                    case PUBLIC, PRIVATE, PKCS1 ->
                        KeyFactory.getInstance(algorithm, factory);
                    case CERTIFICATE, CRL ->
                        CertificateFactory.getInstance(algorithm, factory);
                    default -> null;  // no possible
                };
            }
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * Configures and return a new PEMDecoder instance from the current instance
     * that will use Factory classes from the specified Provider.
     *
     * @param provider the Factory provider.
     * @return a new PEM decoder instance.
     */
    public PEMDecoder withFactory(Provider provider) {
        return new PEMDecoder(provider, password);
    }

    /**
     * Returns a new PEMDecoder instance from the current instance configured
     * to decrypt encrypted PEM data with given password.
     * Non-encrypted PEM may still be decoded from this instance.
     *
     * @param password the password to decrypt encrypted PEM data.
     * @return the decoder
     */
    public PEMDecoder withDecryption(char[] password) {
        Objects.requireNonNull(password);
        return new PEMDecoder(factory, password);
    }
}
