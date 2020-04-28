/**
 *    Copyright 2020 Ray Cole
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package threeguys.http.signing.providers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import threeguys.http.signing.exceptions.KeyNotFoundException;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

public class TestKeyStoreKeyProvider {

    private static final char [] DEFAULT_PASSWORD = "unit-test".toCharArray();

    @Rule
    public TemporaryFolder tempFolder;

    @BeforeClass
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test(expected = KeyNotFoundException.class)
    public void keyNotFound() throws Exception {
        KeyStore keyStore = MockKeys.emptyStore();
        KeyProvider<PrivateKey> privateProvider = new KeyStoreKeyProvider(keyStore, DEFAULT_PASSWORD);
        privateProvider.get("bar");
    }

    @Test
    public void happyCase() throws Exception {
        KeyStore keyStore = MockKeys.emptyStore();
        KeyPair pair = MockKeys.newKeyPair();
        X509Certificate cert = MockKeys.newCertificate(pair);
        keyStore.setKeyEntry("test-key-private", pair.getPrivate(), DEFAULT_PASSWORD, new Certificate[]{ cert });

        KeyProvider<PrivateKey> privateProvider = new KeyStoreKeyProvider(keyStore, DEFAULT_PASSWORD);
        assertEquals(pair.getPrivate(), privateProvider.get("test-key-private"));
    }

    @Test
    public void systemError() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            new KeyStoreKeyProvider(keyStore, DEFAULT_PASSWORD).get("this-will-break");
        } catch (RuntimeException e) {
            assertEquals(KeyStoreException.class, e.getCause().getClass());
        }
    }

}
