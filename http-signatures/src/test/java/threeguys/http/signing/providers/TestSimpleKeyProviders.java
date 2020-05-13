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

import org.junit.jupiter.api.Test;
import threeguys.http.signing.exceptions.KeyNotFoundException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class TestSimpleKeyProviders {

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kp = KeyPairGenerator.getInstance("RSA");
        kp.initialize(1024);
        return kp.generateKeyPair();
    }

    @Test
    public void simpleKeyProviders() throws NoSuchAlgorithmException, KeyNotFoundException {
        KeyPair kp = generateKeyPair();
        SimplePrivateKeyProvider privateProvider = new SimplePrivateKeyProvider(kp.getPrivate());
        assertEquals(kp.getPrivate(), privateProvider.get("foo"));

        SimplePublicKeyProvider publicProvider = new SimplePublicKeyProvider(kp.getPublic());
        assertEquals(kp.getPublic(), publicProvider.get("bar"));

        KeyPair kp2 = generateKeyPair();
        assertNotEquals(kp.getPublic(), kp2.getPublic());
        assertNotEquals(kp.getPrivate(), kp2.getPrivate());

        privateProvider.setKey(kp2.getPrivate());
        assertNotEquals(kp.getPrivate(), privateProvider.get("baz"));
        assertEquals(kp2.getPrivate(), privateProvider.get("yo"));

        publicProvider.setKey(kp2.getPublic());
        assertNotEquals(kp.getPublic(), publicProvider.get("mom"));
        assertEquals(kp2.getPublic(), publicProvider.get("win"));
    }

}
