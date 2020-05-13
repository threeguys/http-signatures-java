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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import threeguys.http.signing.exceptions.SignatureException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TestHttpVerifierAlgorithms {

    public static Stream<Arguments> data() {
        return Stream.of(
                Arguments.of( "rsa-sha256", "RSA", 2048 ),
                Arguments.of( "rsa-sha384", "RSA", 2048 ),
                Arguments.of( "rsa-sha512", "RSA", 2048 ),
                Arguments.of( "ecdsa-sha256", "EC", 256 ),
                Arguments.of( "ecdsa-sha384", "EC", 384 ),
                Arguments.of( "ecdsa-sha512", "EC", 571 )
        );
    }

    @ParameterizedTest
    @MethodSource("data")
    public void happyCase(String algorithm, String keyGenerator, int keySize) throws NoSuchAlgorithmException, SignatureException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyGenerator);
        generator.initialize(keySize, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        Signatures signing = new Signatures();

        PrivateKey key = pair.getPrivate();
        HttpSigner signer = new HttpSignerImpl(algorithm, "test-key", (n) -> key, signing, 300);

        Map<String, String[]> data = new HashMap<>();
        data.put("foo", new String[] { "foo value" });
        data.put("bar", new String[] { "is bar" });
        data.put("baz", new String[] { "was baz,bif,dude"});
        String sig = signer.sign("GET", "/yo/mom", data::get);

        data.put(Signatures.HEADER, new String[] { sig });

        HttpVerifier verifier = new HttpVerifierImpl(signing, (n) -> pair.getPublic());
        VerificationResult result = verifier.verify("GET", "/yo/mom", data::get);
        assertNotNull(result);
    }

}
