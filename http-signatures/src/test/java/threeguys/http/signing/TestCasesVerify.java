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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.providers.MockHeaderProvider;
import threeguys.http.signing.providers.MockKeys;
import threeguys.http.signing.providers.SimplePublicKeyProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.CharBuffer;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static threeguys.http.signing.Signatures.DEFAULT_ALGORITHM;
import static threeguys.http.signing.Signatures.defaultFields;
import static threeguys.http.signing.Signatures.defaultHeadersToInclude;
import static threeguys.http.signing.algorithms.SigningAlgorithms.defaultAlgorithms;


public class TestCasesVerify {

    // more than 1MB of signature in this test will fail
    private static final int MAX_SIG_SIZE = 1024 * 1024;

    private Gson gson = new GsonBuilder().create();

    public static Stream<Arguments> data() {
        return Stream.of(
                Arguments.of( "test.public.pem", "full",    "rsa-sha256", "full" ),
                Arguments.of( "test.public.pem", "full",    "rsa-sha384", "full" ),
                Arguments.of( "test.public.pem", "full",    "rsa-sha512", "full" ),
                Arguments.of( "test.public.pem", "minimal", "rsa-sha256", "minimal" ),
                Arguments.of( "test.public.pem", "minimal", "rsa-sha384", "minimal" ),
                Arguments.of( "test.public.pem", "minimal", "rsa-sha512", "minimal" )
        );
    }

    private Map<String, String> readMap(String path) {
        Type type = new TypeToken<HashMap<String,String>>(){}.getType();
        InputStream is = this.getClass().getClassLoader().getResourceAsStream(path);
        return gson.fromJson(new JsonReader(new InputStreamReader(is)), type);
    }

    private String readSignature(String path) throws IOException {
        try(InputStream is = Objects.requireNonNull(this.getClass().getClassLoader().getResourceAsStream(path))) {
            InputStreamReader rdr = new InputStreamReader(is);
            CharBuffer buffer = CharBuffer.allocate(MAX_SIG_SIZE);
            while(rdr.read(buffer) > 0);
            char [] chars = new char[buffer.position()];
            buffer.position(0);
            buffer.get(chars);
            return new String(chars);
        }
    }

    @ParameterizedTest
    @MethodSource("data")
    public void verify(String key, String name, String sigType, String expectedKey) throws IOException, SignatureException {
        PublicKey publicKey = MockKeys.classpathPublicKey(key);
        Map<String, String> headers = readMap("cases/" + name + "/headers.json");
        Map<String, String> request = readMap("cases/" + name + "/request.json");

        Signatures signatures = new Signatures(DEFAULT_ALGORITHM, defaultAlgorithms(), defaultFields(), defaultHeadersToInclude());
        Clock clock = Clock.fixed(Instant.ofEpochSecond(Long.parseLong(request.get("created"))), ZoneId.of("UTC"));

        MockHeaderProvider hp = new MockHeaderProvider(headers.entrySet());
        String sig = readSignature("cases/" + name + "/signature." + sigType);
        hp.add(Signatures.HEADER, sig);

        HttpVerifierImpl impl = new HttpVerifierImpl(clock, signatures, new SimplePublicKeyProvider(publicKey), 120);

        VerificationResult result = impl.verify(request.get("method"), request.get("url"), hp); //sigHeaders(headers, name, sigType));

        assertEquals(expectedKey, result.getKeyId());
        assertEquals(publicKey, result.getKey());

        assertEquals(new HashSet<>(Signatures.defaultFields()), result.getFields().keySet());
    }

}
