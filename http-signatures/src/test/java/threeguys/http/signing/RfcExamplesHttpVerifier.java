package threeguys.http.signing;

import org.junit.Ignore;
import org.junit.Test;
import threeguys.http.signing.providers.MockHeaderProvider;
import threeguys.http.signing.providers.MockKeys;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;

import static threeguys.http.signing.Signatures.DEFAULT_ALGORITHM;
import static threeguys.http.signing.Signatures.FIELD_CREATED;
import static threeguys.http.signing.Signatures.FIELD_HEADERS;
import static threeguys.http.signing.Signatures.FIELD_KEY_ID;
import static threeguys.http.signing.Signatures.FIELD_SIGNATURE;
import static threeguys.http.signing.Signatures.HEADER;
import static threeguys.http.signing.Signatures.HEADER_CREATED;
import static threeguys.http.signing.Signatures.HEADER_REQUEST_TARGET;
import static threeguys.http.signing.Signatures.defaultAlgorithms;

//
// A.1 Example Keys
//
// A.1.1. rsa-test
//
//    -----BEGIN RSA PUBLIC KEY-----
//    MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
//    WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
//    MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
//    kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
//    uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
//    PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
//    -----END RSA PUBLIC KEY-----
//
//    -----BEGIN RSA PRIVATE KEY-----
//    MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
//    BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
//    JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
//    jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
//    lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
//    SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
//    vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
//    CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
//    +m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
//    yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
//    Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
//    YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
//    cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
//    DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
//    mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
//    qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
//    B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
//    9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
//    f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
//    81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
//    /2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
//    IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
//    qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
//    WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
//    EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
//    -----END RSA PRIVATE KEY-----
//
//  Example Keys:
//  keyId 	Algorithm
//  test-key-a 	hs2019,  using RSASSA-PSS [RFC8017] and SHA-512 [RFC6234]
//  test-key-b 	rsa-256
//
//   ----------------------------------------------------------------
//   A.3. Test Cases - Example HTTP Message:
//
//    POST /foo?param=value&pet=dog HTTP/1.1
//    Host: example.com
//    Date: Tue, 07 Jun 2014 20:51:35 GMT
//    Content-Type: application/json
//    Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
//    Content-Length: 18
//
//    {"hello": "world"}
//
@Ignore
public class RfcExamplesHttpVerifier {

    public static final String METHOD = "POST";
    public static final String URL = "/foo?param=value&pet=dog";

    public MockHeaderProvider headersHttpMessageA3() {
        return new MockHeaderProvider()
                .add("Host", "example.com")
                .add("Date", "Tue, 07 Jun 2014 20:51:35 GMT")
                .add("Content-Type", "application/json")
                .add("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
                .add("Content-Length", "18");
    }

    public MockHeaderProvider headersA3Plus(String ... extra) {
        if ((extra.length & 0x1) == 0x1) {
            throw new IllegalArgumentException("Must have an even number of arguments: (key, value)");
        }

        MockHeaderProvider hp = headersHttpMessageA3();
        for (int i=0; i<extra.length; i+=2) {
            hp.add(extra[i], extra[i+1]);
        }
        return hp;
    }


//
// Test Case A.3.1.1
//
//   https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-a.3.1.1
//
// A.3.1.1. hs2019 signature over minimal recommended content
//                 Algorithm: hs2019, using RSASSA-PSS [RFC8017] using SHA-512 [RFC6234]
//           Covered Content: (created) (request-target)
//             Creation Time: 8:51:35 PM GMT, June 7th, 2014
//           Expiration Time: Undefined
// Verification Key Material: A.1.1 - rsa-test
//
//    The Signature Input is:
//            (created): 1402170695
//            (request-target): post /foo?param=value&pet=dog
//
//    The signature value is:
//
//    e3y37nxAoeuXw2KbaIxE2d9jpE7Z9okgizg6QbD2Z7fUVUvog+ZTKKLRBnhNglVIY6fAa
//    YlHwx7ZAXXdBVF8gjWBPL6U9zRrB4PFzjoLSxHaqsvS0ZK9FRxpenptgukaVQ1aeva3PE
//    1aD6zZ93df2lFIFXGDefYCQ+M/SrDGQOFvaVykEkte5mO6zQZ/HpokjMKvilfSMJS+vbv
//    C1GJItQpjs636Db+7zB2W1BurkGxtQdCLDXuIDg4S8pPSDihkch/dUzL2BpML3PXGKVXw
//    HOUkVG6Q2ge07IYdzya6N1fIVA9eKI1Y47HT35QliVAxZgE0EZLo8mxq19ReIVvuFg==
//
//    A possible Signature header for this signature is:
//
//    Signature: keyId="test-key-a", created=1402170695,
//      headers="(created) (request-target)",
//      signature="e3y37nxAoeuXw2KbaIxE2d9jpE7Z9okgizg6QbD2Z7fUVUvog+ZTKK
//        LRBnhNglVIY6fAaYlHwx7ZAXXdBVF8gjWBPL6U9zRrB4PFzjoLSxHaqsvS0ZK
//        9FRxpenptgukaVQ1aeva3PE1aD6zZ93df2lFIFXGDefYCQ+M/SrDGQOFvaVyk
//        Ekte5mO6zQZ/HpokjMKvilfSMJS+vbvC1GJItQpjs636Db+7zB2W1BurkGxtQ
//        dCLDXuIDg4S8pPSDihkch/dUzL2BpML3PXGKVXwHOUkVG6Q2ge07IYdzya6N1
//        fIVA9eKI1Y47HT35QliVAxZgE0EZLo8mxq19ReIVvuFg=="

    String signatureA311 =
        "keyId=\"test-key-a\", created=1402170695, " +
            "headers=\"(created) (request-target)\", " +
            "signature=\"e3y37nxAoeuXw2KbaIxE2d9jpE7Z9okgizg6QbD2Z7fUVUvog+ZTKK" +
                "LRBnhNglVIY6fAaYlHwx7ZAXXdBVF8gjWBPL6U9zRrB4PFzjoLSxHaqsvS0ZK" +
                "9FRxpenptgukaVQ1aeva3PE1aD6zZ93df2lFIFXGDefYCQ+M/SrDGQOFvaVyk" +
                "Ekte5mO6zQZ/HpokjMKvilfSMJS+vbvC1GJItQpjs636Db+7zB2W1BurkGxtQ" +
                "dCLDXuIDg4S8pPSDihkch/dUzL2BpML3PXGKVXwHOUkVG6Q2ge07IYdzya6N1" +
                "fIVA9eKI1Y47HT35QliVAxZgE0EZLo8mxq19ReIVvuFg==\"";

    @Test
    public void verifyA311_hs2019_signature_over_minimal_recommended_content() throws Exception {
        MockHeaderProvider hp = headersA3Plus(HEADER, signatureA311);
        List<String> headersToInclude = Arrays.asList(HEADER_REQUEST_TARGET, HEADER_CREATED);
        List<String> fields = Arrays.asList(FIELD_KEY_ID, FIELD_CREATED, FIELD_HEADERS, FIELD_SIGNATURE);
        Signatures signatures = new Signatures("rsapss-sha512", defaultAlgorithms(), fields, headersToInclude);
        PublicKey publicKey = MockKeys.classpathPublicKey("rfc.public.pem");

        Clock clock = Clock.fixed(Instant.ofEpochSecond(1402170695), ZoneId.of("UTC"));
        HttpVerifierImpl verifier = new HttpVerifierImpl(clock, signatures, (n) -> publicKey, 3600);
        VerificationResult result = verifier.verify(METHOD, URL, hp);
        System.out.println(result.getFields());
    }

}
