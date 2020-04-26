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

import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.exceptions.MissingHeadersException;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.providers.HeaderProvider;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class RequestSigning {

    public static final String HEADER = "Signature";

    public static final String FIELD_ALGORITHM = "algorithm";
    public static final String FIELD_KEY_ID = "keyId";
    public static final String FIELD_CREATED = "created";
    public static final String FIELD_EXPIRES = "expires";
    public static final String FIELD_HEADERS = "headers";
    public static final String FIELD_SIGNATURE = "signature";

    public static final String HEADER_REQUEST_TARGET = "(request-target)";
    public static final String HEADER_CREATED = "(created)";

    private final Map<String, String> algorithms;
    private final List<String> fields;
    private final Set<String> fieldIndex;

    public RequestSigning() {
        this(defaultAlgorithms(), defaultFields());
    }

    public RequestSigning(Map<String, String> algorithms, List<String> fields) {
        this.algorithms = algorithms;
        this.fields = Collections.unmodifiableList(fields);
        this.fieldIndex = Collections.unmodifiableSet(new HashSet<>(fields));
    }

    public static Map<String, String> defaultAlgorithms() {
        Map<String, String> algos = new HashMap<>();
        algos.put("rsa-sha256", "SHA256withRSA");
        algos.put("rsa-sha384", "SHA384withRSA");
        algos.put("rsa-sha512", "SHA512withRSA");
        algos.put("ecdsa-sha256", "SHA256withECDSA");
        algos.put("ecdsa-sha384", "SHA384withECDSA");
        algos.put("ecdsa-sha512", "SHA512withECDSA");
        return Collections.unmodifiableMap(algos);
    }

    public static List<String> defaultFields() {
        return Arrays.asList(
            FIELD_ALGORITHM, FIELD_KEY_ID, FIELD_CREATED, FIELD_EXPIRES, FIELD_HEADERS, FIELD_SIGNATURE
        );
    }

    public static Pattern defaultKeyIdFormat() {
        return Pattern.compile("[a-zA-Z0-9.#$!?@^&*()\\[\\]/\\\\'+=_-]");
    }

    public Signature getSignature(String algorithm) throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithms.get(algorithm));
    }

    public Map<String, String> getAlgorithms() {
        return algorithms;
    }

    public List<String> getFields() {
        return fields;
    }

    public boolean validField(String field) {
        return fieldIndex.contains(field);
    }

    public String canonicalize(String header, String [] values) {
        return String.format("%s: %s", header.toLowerCase().trim(),
                Arrays.stream(values)
                        .map(String::trim)
                        .collect(Collectors.joining(", ")));
    }

    public byte[] assemblePayload(String method, String url, List<String> headers, HeaderProvider provider, long created) throws SignatureException {
        try {
            StringBuilder sb = new StringBuilder();

            for (String hdr : headers) {
                String value;
                if (HEADER_CREATED.equals(hdr)) {
                    value = String.format("%s: %d", HEADER_CREATED, created);
                } else if (HEADER_REQUEST_TARGET.equals(hdr)) {
                    String canonicalTarget = String.format("%s %s", method.toLowerCase().trim(), url.trim());
                    value = String.format("%s: %s", HEADER_REQUEST_TARGET, canonicalTarget);
                } else {
                    String[] values = provider.get(hdr);
                    value = canonicalize(hdr, values);
                }
                sb.append(value).append("\n");
            }

            return sb.toString().getBytes(StandardCharsets.UTF_8);

        } catch (Exception e) {
            if (e instanceof InvalidSignatureException) {
                throw (InvalidSignatureException) e;
            } else {
                throw new MissingHeadersException(e);
            }
        }
    }

}
