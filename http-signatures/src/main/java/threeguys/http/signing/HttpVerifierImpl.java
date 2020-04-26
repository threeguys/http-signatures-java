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

import threeguys.http.signing.exceptions.ExpiredSignatureException;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.providers.HeaderProvider;
import threeguys.http.signing.providers.KeyProvider;

import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static threeguys.http.signing.RequestSigning.FIELD_ALGORITHM;
import static threeguys.http.signing.RequestSigning.FIELD_CREATED;
import static threeguys.http.signing.RequestSigning.FIELD_EXPIRES;
import static threeguys.http.signing.RequestSigning.FIELD_HEADERS;
import static threeguys.http.signing.RequestSigning.FIELD_KEY_ID;
import static threeguys.http.signing.RequestSigning.FIELD_SIGNATURE;
import static threeguys.http.signing.RequestSigning.HEADER;

public class HttpVerifierImpl implements HttpVerifier {

    private final RequestSigning signing;
    private final KeyProvider<PublicKey> keyProvider;
    private final long maxCreateAgeSec;

    public HttpVerifierImpl(RequestSigning signing, KeyProvider<PublicKey> keyProvider) {
        this(signing, keyProvider, Long.MAX_VALUE);
    }

    public HttpVerifierImpl(RequestSigning signing, KeyProvider<PublicKey> keyProvider, long maxCreateAgeSec) {
        this.signing = signing;
        this.keyProvider = keyProvider;
        this.maxCreateAgeSec = maxCreateAgeSec;
    }

    public RequestSigning getSigning() {
        return signing;
    }

    public KeyProvider<PublicKey> getKeyProvider() {
        return keyProvider;
    }

    public long getMaxCreateAgeSec() {
        return maxCreateAgeSec;
    }

    private void checkField(Map<String, String> fields, String field) throws SignatureException {
        if (fields.containsKey(field)) {
            throw new InvalidSignatureException(String.format("Field %s occurred more than once", field));
        }
    }

    private String fixQuotes(String value) {
        if (value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length()-1);
        }
        return value;
    }

    public static <R> Predicate<R> not(Predicate<R> predicate) {
        return predicate.negate();
    }

    private Map<String, String> parseFields(String signatureValue) throws SignatureException {
        Pattern regex = Pattern.compile("([^=]+)=(\"[^\"]+\"|[0-9]+)(, ){0,1}(.*)");

        // Parse fields from the header
        Map<String, String> fields = new HashMap<>();
        String working = signatureValue;
        while(working.length() > 0) {

            Matcher m = regex.matcher(working);
            if (m.lookingAt()) {
                String name = m.group(1);
                String value = m.group(2);

                if (!signing.validField(name)) {
                    throw new InvalidSignatureException(String.format("Unknown field %s", name));
                }

                checkField(fields, name);
                fields.put(name, fixQuotes(value));

                working = m.group(4);
            } else {
                throw new InvalidSignatureException("Invalid format: " + working);
            }
        }

        // Verify all of the fields are there
        String missing = fields.keySet().stream().filter(not(signing::validField))
                .collect(Collectors.joining(", "));

        if (missing.length() > 0) {
            throw new InvalidSignatureException(String.format("Field(s) %s missing", missing));
        }

        return fields;
    }

    public VerificationResult verify(String method, String url, HeaderProvider provider) throws SignatureException {
        try {
            String [] signatureValues = provider.get(HEADER);
            if (signatureValues == null || signatureValues.length == 0) {
                throw new InvalidSignatureException("Could not find header \"" + HEADER + "\"");
            }
            String signatureValue = signatureValues[0];

            Map<String, String> fields = parseFields(signatureValue);

            List<String> headers = Arrays.asList(fields.get(FIELD_HEADERS).split(" "));

            // Validate the timestamps in the signature
            long created = Long.parseLong(fields.get(FIELD_CREATED));
            long expires = Long.parseLong(fields.get(FIELD_EXPIRES));

            long now = Instant.now().getEpochSecond();
            long checkCreate = now - maxCreateAgeSec;

            if (checkCreate > created) {
                throw new ExpiredSignatureException(String.format("Create time of %d is too far in the past, check = %d", created, checkCreate));
            }

            if (now > expires) {
                throw new ExpiredSignatureException(String.format("Signature %d is expired, check = %d", expires, now));
            }

            // Check the key parameters
            // these will throw exceptions if the values are not found
            String algorithm = fields.get(FIELD_ALGORITHM);
            Signature signature = signing.getSignature(algorithm);

            String keyId = fields.get(FIELD_KEY_ID);
            PublicKey key = keyProvider.get(keyId);

            // Verify the signature
            signature.initVerify(key);

            byte [] payload = signing.assemblePayload(method, url, headers, provider, created);
            signature.update(payload);

            byte [] data = Base64.getDecoder().decode(fields.get(FIELD_SIGNATURE));
            if (!signature.verify(data)) {
                throw new InvalidSignatureException("The signature was not verified");
            }

            // Woot! we're good!
            return new VerificationResult(key, fields);

        } catch (Exception e) {
            if (e instanceof SignatureException) {
                throw (SignatureException) e;
            } else {
                throw new SignatureException(e);
            }
        }
    }

}
