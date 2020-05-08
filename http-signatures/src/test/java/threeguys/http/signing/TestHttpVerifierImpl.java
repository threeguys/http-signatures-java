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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import threeguys.http.signing.providers.MockHeaderProvider;
import threeguys.http.signing.providers.MockKeys;
import threeguys.http.signing.providers.SimplePublicKeyProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static threeguys.http.signing.Signatures.DEFAULT_ALGORITHM;
import static threeguys.http.signing.Signatures.FIELD_CREATED;
import static threeguys.http.signing.Signatures.FIELD_HEADERS;
import static threeguys.http.signing.Signatures.FIELD_KEY_ID;
import static threeguys.http.signing.Signatures.FIELD_SIGNATURE;
import static threeguys.http.signing.Signatures.HEADER;
import static threeguys.http.signing.Signatures.HEADER_CREATED;
import static threeguys.http.signing.Signatures.HEADER_REQUEST_TARGET;
import static threeguys.http.signing.Signatures.defaultFields;
import static threeguys.http.signing.Signatures.defaultHeadersToInclude;
import static threeguys.http.signing.algorithms.SigningAlgorithms.defaultAlgorithms;

public class TestHttpVerifierImpl {

    @BeforeClass
    public static void setup() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void rfcExample() throws Exception {
        // https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-a.3.1.1

        String signature = "keyId=\"test-key-a\", created=1402170695, headers=\"(created) (request-target)\", " +
                "signature=\"e3y37nxAoeuXw2KbaIxE2d9jpE7Z9okgizg6QbD2Z7fUVUvog+ZTKK" +
                "LRBnhNglVIY6fAaYlHwx7ZAXXdBVF8gjWBPL6U9zRrB4PFzjoLSxHaqsvS0ZK" +
                "9FRxpenptgukaVQ1aeva3PE1aD6zZ93df2lFIFXGDefYCQ+M/SrDGQOFvaVyk" +
                "Ekte5mO6zQZ/HpokjMKvilfSMJS+vbvC1GJItQpjs636Db+7zB2W1BurkGxtQ" +
                "dCLDXuIDg4S8pPSDihkch/dUzL2BpML3PXGKVXwHOUkVG6Q2ge07IYdzya6N1" +
                "fIVA9eKI1Y47HT35QliVAxZgE0EZLo8mxq19ReIVvuFg==\"";

        String input = "(created): 1402170695\n" +
                "(request-target): post /foo?param=value&pet=dog";

        String method = "POST";
        String url = "/foo?param=value&pet=dog";

        MockHeaderProvider hp = new MockHeaderProvider()
                .add("Host", "example.com")
                .add("Date", "Tue, 07 Jun 2014 20:51:35 GMT")
                .add("Content-Type", "application/json")
                .add("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
                .add("Content-Length", "18")
                .add(HEADER, signature);

        List<String> headersToInclude = Arrays.asList(HEADER_REQUEST_TARGET, HEADER_CREATED);
        List<String> fields = Arrays.asList(FIELD_KEY_ID, FIELD_CREATED, FIELD_HEADERS, FIELD_SIGNATURE);
        Signatures signatures = new Signatures("rsa-sha256", defaultAlgorithms(), fields, headersToInclude);
        PublicKey publicKey = MockKeys.classpathPublicKey("test.public.pem");

        Clock clock = Clock.fixed(Instant.ofEpochSecond(1402170695), ZoneId.of("UTC"));
        HttpVerifierImpl verifier = new HttpVerifierImpl(clock, signatures, (n) -> publicKey, 3600);
        VerificationResult result = verifier.verify(method, url, hp);
        assertEquals("test-key-a", result.getKeyId());
        assertEquals(publicKey, result.getKey());
        assertEquals("rsa-sha256", result.getAlgorithm());

        Map<String, String> expected = new HashMap<>();
        expected.put(FIELD_KEY_ID, "test-key-a");
        expected.put(FIELD_CREATED, "1402170695");
        expected.put(FIELD_HEADERS, "(created) (request-target)");
        expected.put(FIELD_SIGNATURE, "e3y37nxAoeuXw2KbaIxE2d9jpE7Z9okgizg6QbD2Z7fUVUvog+ZTKK" +
                "LRBnhNglVIY6fAaYlHwx7ZAXXdBVF8gjWBPL6U9zRrB4PFzjoLSxHaqsvS0ZK" +
                "9FRxpenptgukaVQ1aeva3PE1aD6zZ93df2lFIFXGDefYCQ+M/SrDGQOFvaVyk" +
                "Ekte5mO6zQZ/HpokjMKvilfSMJS+vbvC1GJItQpjs636Db+7zB2W1BurkGxtQ" +
                "dCLDXuIDg4S8pPSDihkch/dUzL2BpML3PXGKVXwHOUkVG6Q2ge07IYdzya6N1" +
                "fIVA9eKI1Y47HT35QliVAxZgE0EZLo8mxq19ReIVvuFg==");
        assertEquals(expected, result.getFields());
    }

    String payload =
            "(request-target): get /something\n"
            + "(created): 12345678\n"
            + "(expires): 12345778\n"
            + "content-type: application/json\n"
            + "content-md5: 1B2M2Y8AsgTpgAmY7PhCfg==\n"
            + "content-length: 14\n"
            + "x-custom-header: yo man!\n";

//    "e3y37nxAoeuXw2KbaIxE2d9jpE7Z9okgizg6QbD2Z7fUVUvog+ZTKKLRBnhNglVIY6fAa"
//    "YlHwx7ZAXXdBVF8gjWBPL6U9zRrB4PFzjoLSxHaqsvS0ZK9FRxpenptgukaVQ1aeva3PE"
//    "1aD6zZ93df2lFIFXGDefYCQ+M/SrDGQOFvaVykEkte5mO6zQZ/HpokjMKvilfSMJS+vbv"
//    "C1GJItQpjs636Db+7zB2W1BurkGxtQdCLDXuIDg4S8pPSDihkch/dUzL2BpML3PXGKVXw"
//    "HOUkVG6Q2ge07IYdzya6N1fIVA9eKI1Y47HT35QliVAxZgE0EZLo8mxq19ReIVvuFg=="

    // TODO This test needs some work
    @Test
    public void something() throws Exception {
        byte [] postData = "{\"data\": 42.0}".getBytes(StandardCharsets.UTF_8);
        PublicKey publicKey = MockKeys.classpathPublicKey("test.public.pem");
        PrivateKey privateKey = MockKeys.classpathPrivateKey("test.private.pem");

        MessageDigest md = MessageDigest.getInstance("MD5");
        md.digest(postData);
        String contentHash = Base64.getEncoder().encodeToString(md.digest());


        String sigBase64 = "myJ+RYpiZ0HKD3GfXGpybD9MNmzW3VnWetuITbSjbDw1kuOXynoqgn6/NIl+5Lzs5CRWeGiggq74IVGMXMR8r2FtACs3XQfpWuANeALlajdpMdtP+v0n9LJQqaZVGf+NorStNrD9Z6XhGwBWgYtwOpogm2ZUhSpiySZ26laOQ9U=";

        List<String> headersToInclude = new ArrayList<>(defaultHeadersToInclude());
        headersToInclude.add("X-Custom-Header");

        Signatures signatures = new Signatures(DEFAULT_ALGORITHM, defaultAlgorithms(), defaultFields(), headersToInclude);
        Clock clock = Clock.fixed(Instant.ofEpochSecond(12345678), ZoneId.of("UTC"));

        // TODO This is wonky, need to clean how headers are found
        MockHeaderProvider hp = new MockHeaderProvider()
                .add("Content-Type", "application/json")
                .add("content-type", "application/json")
                .add("Content-Length", Integer.toString(postData.length))
                .add("content-length", Integer.toString(postData.length))
                .add("Content-MD5", contentHash)
                .add("content-md5", contentHash)
                .add("X-Custom-Header", "yo man!")
                .add("x-custom-header", "yo man!");

        HttpSignerImpl signer = new HttpSignerImpl(clock, "rsa-sha256", "unit-test", (n) -> privateKey, signatures, 100);

        System.out.println("------------- BEGIN SIGNING ---------------------");
        String signature = signer.sign("POST", "/something", hp);
        System.out.println("SIGNATURE: " + signature.replace(",", ",\n    "));
        System.out.println("------------- END SIGNING ---------------------");

        hp.add(HEADER, signature);

        HttpVerifierImpl impl = new HttpVerifierImpl(clock, signatures, new SimplePublicKeyProvider(publicKey), 120);

        System.out.println("------------- BEGIN VERIFY ---------------------");
        impl.verify("POST", "/something", hp);
        System.out.println("------------- END VERIFY ---------------------");
    }

}
