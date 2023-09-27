/*
 * TODO: Copyright goes here
 */

/*
 * @test
 * @summary check that the provider properties for PEM keystore are available
 * @author  Karl Scheibelhofer
 */

import java.security.Provider;
import java.security.Security;

public class PemKeystoreProviderTest {

    public static void main(String[] args) throws Exception {
        checkProperty("SUN", "KeyStore.PEM");
        checkProperty("SUN", "KeyStore.PEM-DIRECTORY");
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
}
