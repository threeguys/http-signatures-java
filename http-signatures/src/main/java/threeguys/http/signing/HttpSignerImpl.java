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

import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static threeguys.http.signing.Signatures.FIELD_ALGORITHM;
import static threeguys.http.signing.Signatures.FIELD_CREATED;
import static threeguys.http.signing.Signatures.FIELD_EXPIRES;
import static threeguys.http.signing.Signatures.FIELD_HEADERS;
import static threeguys.http.signing.Signatures.FIELD_KEY_ID;
import static threeguys.http.signing.Signatures.FIELD_SIGNATURE;

public class HttpSignerImpl implements HttpSigner {

    private final Clock clock;
    private final String algorithm;
    private String keyId;
    private final KeyProvider<PrivateKey> privateKey;
    private final Signatures signing;
    private final int expirationSec;

    private String algorithmValue;

    public HttpSignerImpl(String algorithm, String keyId, KeyProvider<PrivateKey> privateKey, Signatures signing, int expirationSec) throws InvalidSignatureException {
        this(Clock.systemUTC(), algorithm, keyId, privateKey, signing, expirationSec);
    }

    public HttpSignerImpl(Clock clock, String algorithm, String keyId, KeyProvider<PrivateKey> privateKey, Signatures signing, int expirationSec) throws InvalidSignatureException {
        this.clock = clock;
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.privateKey = privateKey;
        this.signing = signing;
        this.expirationSec = expirationSec;

        // These are just optimizations
        this.algorithmValue = makeValue(algorithm);
    }

    private String makeValue(String value) throws InvalidSignatureException {
        if (value.contains("\"")) {
            throw new InvalidSignatureException("Values cannot contain '\"'");
        }

        return "\"" + value + "\"";
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    @Override
    public String sign(String method, String url, HeaderProvider provider) throws InvalidSignatureException {
        try {
            String reqKeyId = this.keyId; // just so it doesn't switch out while we're processing
            PrivateKey key = privateKey.get(reqKeyId);

            long created = clock.instant().getEpochSecond();
            long expires = created + expirationSec;
            Payload payload = signing.assemblePayload(method, url, provider, created, expires);

            // Create the signature
            Signature signature = signing.getSignature(algorithm);
            signature.initSign(key);
            signature.update(payload.getPlaintext());
            byte [] data = signature.sign();
            String encodedSig = Base64.getEncoder().encodeToString(data);

            List<String> output = new ArrayList<>();
            for (String f : signing.getFields()) {
                String value;
                switch(f) {
                    case FIELD_ALGORITHM :
                        value = algorithmValue;
                        break;
                    case FIELD_KEY_ID:
                        value = makeValue(reqKeyId);
                        break;
                    case FIELD_CREATED:
                        value = Long.toString(created);
                        break;
                    case FIELD_EXPIRES:
                        value = Long.toString(expires);
                        break;
                    case FIELD_HEADERS:
                        value = makeValue(payload.getHeaders());
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
