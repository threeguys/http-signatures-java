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
package threeguys.http.signing;

import org.junit.Test;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class TestVerificationResult {

    @Test
    public void smokeTest() {

        PublicKey pk = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return null;
            }

            @Override
            public String getFormat() {
                return null;
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };

        Map<String, String> fields = new HashMap<>();
        fields.put(Signatures.FIELD_ALGORITHM, "test-algo");
        fields.put(Signatures.FIELD_KEY_ID, "test-key-id");

        VerificationResult r = new VerificationResult(pk, fields);
        assertEquals(pk, r.getKey());
        assertEquals("test-algo", r.getAlgorithm());
        assertEquals("test-key-id", r.getKeyId());
        assertEquals(fields, r.getFields());
    }

}
