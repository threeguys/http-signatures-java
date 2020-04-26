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

import threeguys.http.signing.exceptions.InvalidFieldException;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.exceptions.MissingHeadersException;
import threeguys.http.signing.providers.HeaderProvider;
import threeguys.http.signing.providers.KeyProvider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import static threeguys.http.signing.RequestSigning.FIELD_ALGORITHM;
import static threeguys.http.signing.RequestSigning.FIELD_CREATED;
import static threeguys.http.signing.RequestSigning.FIELD_EXPIRES;
import static threeguys.http.signing.RequestSigning.FIELD_HEADERS;
import static threeguys.http.signing.RequestSigning.FIELD_KEY_ID;
import static threeguys.http.signing.RequestSigning.FIELD_SIGNATURE;

public class HttpSigner {

    private final String algorithm;
    private final String keyId;
    private final KeyProvider<PrivateKey> privateKey;
    private final List<String> headers;
    private final RequestSigning signing;
    private final int expirationSec;

    public HttpSigner(String algorithm, String keyId, KeyProvider<PrivateKey> privateKey, List<String> headers, RequestSigning signing, int expirationSec) {
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.privateKey = privateKey;
        this.headers = headers;
        this.signing = signing;
        this.expirationSec = expirationSec;
    }

    private String makeValue(String value) throws InvalidSignatureException {
        if (value.contains("\"")) {
            throw new InvalidSignatureException("Values cannot contain '\"'");
        }

        return "\"" + value + "\"";
    }

    private String signPayload(String algorithm, PrivateKey privateKey, byte [] payload) throws InvalidSignatureException {
        try {
            Signature signature = signing.getSignature(algorithm);
            signature.initSign(privateKey);
            signature.update(payload);
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | java.security.SignatureException e) {
            throw new InvalidSignatureException(e);
        }
    }

    public String sign(String method, String url, HeaderProvider provider) throws InvalidSignatureException {
        try {
            long created = Instant.now().getEpochSecond();
            byte [] payload = signing.assemblePayload(method, url, headers, provider, created);
            String encodedSig = signPayload(algorithm, privateKey.get(keyId), payload);

            List<String> output = new ArrayList<>();
            for (String f : signing.getFields()) {
                String value;
                switch(f) {
                    case FIELD_ALGORITHM :
                        value = makeValue(algorithm);
                        break;
                    case FIELD_KEY_ID:
                        value = makeValue(keyId);
                        break;
                    case FIELD_CREATED:
                        value = Long.toString(created);
                        break;
                    case FIELD_EXPIRES:
                        value = Long.toString(created + expirationSec);
                        break;
                    case FIELD_HEADERS:
                        value = makeValue(headers.stream()
                                .map(String::toLowerCase)
                                .map(String::trim)
                                .collect(Collectors.joining(" ")));
                        break;
                    case FIELD_SIGNATURE:
                        value = makeValue(encodedSig);
                        break;
                    default:
                        throw new InvalidFieldException("Unknown field: " + f);
                }
                output.add(f + "=" + value);
            }

            if (output.size() == 0) {
                throw new MissingHeadersException("No fields were found to include in the signature!");
            }

            return String.join(", ", output);

        } catch (Exception e) {
            if (e instanceof InvalidSignatureException) {
                throw (InvalidSignatureException) e;
            } else {
                throw new InvalidSignatureException(e);
            }
        }
    }

}
