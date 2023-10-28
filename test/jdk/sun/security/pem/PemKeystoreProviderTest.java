/*
 * TODO: Copyright goes here
 */

/*
 * @test
 * @summary check that the provider properties for PEM keystore are available
 * @author  Karl Scheibelhofer
 */

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

public class PemKeystoreProviderTest {

    private static final String PROVIDER = "SUN";

    public static void main(String[] args) throws Exception {
        checkProperty(PROVIDER, "KeyStore.PEM");
        checkProperty(PROVIDER, "KeyStore.PEM-DIRECTORY");

        checkGetInstance(PROVIDER, "PEM");
        checkGetInstance(PROVIDER, "pem");
        checkGetInstance(PROVIDER, "Pem");
        checkGetInstance(PROVIDER, "PEM-DIRECTORY");
        checkGetInstance(PROVIDER, "pem-directory");
        checkGetInstance(PROVIDER, "Pem-Directory");
    }

    private static void checkProperty(String providerName, String propertyName) throws Exception {
        Provider provider = Security.getProvider(providerName);
        String propertyValue = provider.getProperty(propertyName);

        Assertions.assertNotNull(propertyValue, "value of property " + propertyName + " of provider " + providerName + " is null");
        Assertions.assertTrue(!propertyValue.isEmpty(), "value of property " + propertyName + " of provider " + providerName + " is empty");

        System.out.println("OK: provider=" + providerName + ", property=" + propertyName + ", value=" + propertyValue);
    }

    private static void checkGetInstance(String providerName, String keystoreType) throws Exception {
        KeyStore keystoreInstance = KeyStore.getInstance(keystoreType, providerName);

        Assertions.assertNotNull(keystoreInstance, "getting keystore instance of type " + keystoreType + " of provider " + providerName + " returned null");

        System.out.println("OK: keystore instance provider=" + providerName + ", type=" + keystoreType);
    }

}
