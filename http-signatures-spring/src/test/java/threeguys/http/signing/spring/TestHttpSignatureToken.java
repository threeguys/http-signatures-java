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
package threeguys.http.signing.spring;

import org.junit.Test;

import java.security.PublicKey;
import java.util.Collections;

import static org.junit.Assert.*;

public class TestHttpSignatureToken {

    @Test
    public void happyCase() {
        HttpSignatureUser user = new HttpSignatureUser("unit-test-user");
        String algorithm = "unit-test-algo";
        String keyId = "unit-test-key";

        PublicKey key = new MockPublicKey();
        HttpSignatureToken token = new HttpSignatureToken(user, algorithm, keyId, key, Collections.emptyList());

        assertEquals("unit-test-algo", token.getAlgorithm());
        assertEquals("unit-test-key", token.getKeyId());
        assertEquals(user, token.getPrincipal());
        assertEquals(key, token.getCredentials());
        assertEquals(Collections.emptyList(), token.getAuthorities());
    }

}
