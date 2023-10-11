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

    public static void main(String[] args) throws Exception {
        checkProperty("SUN", "KeyStore.PEM");
        checkProperty("SUN", "KeyStore.PEM-DIRECTORY");

        checkGetInstance("SUN", "PEM");
        checkGetInstance("SUN", "PEM-DIRECTORY");
    }

    private static void checkProperty(String providerName, String propertyName) throws Exception {
        Provider provider = Security.getProvider(providerName);
        String propertyValue = provider.getProperty(propertyName);

        if (propertyValue == null) {
            throw new Exception("value of property " + propertyName + " of provider " + providerName + " is null");
        }
        if (propertyValue.isEmpty()) {
            throw new Exception("value of property " + propertyName + " of provider " + providerName + " is empty");
        }

        System.out.println("OK: provider=" + providerName + ", property=" + propertyName + ", value=" + propertyValue);
    }

    private static void checkGetInstance(String providerName, String keystoreType) throws Exception {
        KeyStore keystoreInstance = KeyStore.getInstance(keystoreType, providerName);

        if (keystoreInstance == null) {
            throw new Exception("getting keystore instance of type " + keystoreType + " of provider " + providerName + " returned null");
        }

        System.out.println("OK: keystore instance provider=" + providerName + ", type=" + keystoreType);
    }

}
