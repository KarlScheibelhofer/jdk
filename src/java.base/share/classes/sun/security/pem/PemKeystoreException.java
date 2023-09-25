package sun.security.pem;

/**
 * Wrapper exception to simplify exception handling.
 */
public class PemKeystoreException extends RuntimeException {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    PemKeystoreException(String message, Throwable cause) {
        super(message, cause);
    }

}
