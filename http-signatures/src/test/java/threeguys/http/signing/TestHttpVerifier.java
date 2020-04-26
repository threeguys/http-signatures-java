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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.providers.HeaderProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class TestHttpVerifier {

    private static class MockHeaderProvider implements HeaderProvider {

        private Map<String, String[]> data;

        public MockHeaderProvider(Map<String, String[]> data) {
            this.data = data;
        }

        @Override
        public String[] get(String name) throws Exception {
            String [] result = data.get(name);
            if (result == null) {
                throw new IllegalArgumentException(name);
            }
            return result;
        }
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "rsa-sha256", "RSA", 2048 },
                { "rsa-sha384", "RSA", 2048 },
                { "rsa-sha512", "RSA", 2048 },
                { "ecdsa-sha256", "EC", 256 },
                { "ecdsa-sha384", "EC", 384 },
                { "ecdsa-sha512", "EC", 571 },
        });
    }

    private String algorithm;
    private String keyGenerator;
    private int keySize;

    public TestHttpVerifier(String algorithm, String keyGenerator, int keySize) {
        this.algorithm = algorithm;
        this.keyGenerator = keyGenerator;
        this.keySize = keySize;
    }

    @Test
    public void runHappyCase() throws NoSuchAlgorithmException, SignatureException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyGenerator);
        generator.initialize(keySize, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        RequestSigning signing = new RequestSigning();

        PrivateKey key = pair.getPrivate();
        List<String> headers = Arrays.asList(RequestSigning.HEADER_REQUEST_TARGET, RequestSigning.HEADER_CREATED, "foo", "bar", "baz");
        HttpSigner signer = new HttpSigner(algorithm, "test-key", (n) -> key, headers, signing, 300);

        Map<String, String[]> data = new HashMap<>();
        data.put("foo", new String[] { "foo value" });
        data.put("bar", new String[] { "is bar" });
        data.put("baz", new String[] { "was baz,bif,dude"});
        MockHeaderProvider provider = new MockHeaderProvider(data);

        String sig = signer.sign("GET", "/yo/mom", provider);

        data.put(RequestSigning.HEADER, new String[] { sig });

        HttpVerifier verifier = new HttpVerifier(signing, (n) -> pair.getPublic());
        VerificationResult result = verifier.verify("GET", "/yo/mom", provider);
        assertNotNull(result);
    }

}
