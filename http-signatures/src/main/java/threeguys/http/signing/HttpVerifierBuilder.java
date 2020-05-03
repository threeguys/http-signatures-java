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

import threeguys.http.signing.algorithms.SigningAlgorithm;
import threeguys.http.signing.algorithms.SigningAlgorithms;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.providers.KeyProvider;

import java.security.PublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpVerifierBuilder {

    public static final int DEFAULT_MAX_AGE_SEC = 300;

    private KeyProvider<PublicKey> keyProvider;
    private Map<String, SigningAlgorithm> algorithms;
    private String algorithmList;
    private List<String> fields;
    private List<String> headersToInclude;
    private String fieldList;
    private int maxAge = -1;
    private Clock clock;

    public HttpVerifierBuilder withAlgorithms(Map<String, SigningAlgorithm> algorithms) {
        this.algorithms = algorithms;
        return this;
    }

    public HttpVerifierBuilder withAlgorithmList(String algorithmList) {
        this.algorithmList = algorithmList;
        return this;
    }

    public HttpVerifierBuilder withFields(List<String> fields) {
        this.fields = fields;
        return this;
    }

    public HttpVerifierBuilder withFieldList(String fieldList) {
        this.fieldList = fieldList;
        return this;
    }

    public HttpVerifierBuilder withHeadersToInclude(List<String> headersToInclude) {
        this.headersToInclude = headersToInclude;
        return this;
    }

    public HttpVerifierBuilder withMaxAge(int maxAge) {
        this.maxAge = maxAge;
        return this;
    }

    public HttpVerifierBuilder withClock(Clock clock) {
        this.clock = clock;
        return this;
    }

    public HttpVerifierBuilder withMaxAge(String maxAge) {
        return withMaxAge(Integer.parseInt(maxAge));
    }

    public HttpVerifierBuilder withKeyProvider(KeyProvider<PublicKey> keyProvider) {
        this.keyProvider = keyProvider;
        return this;
    }

    public static List<String> parseFieldList(String entry) throws SignatureException {
        String [] entries = entry.split(",");
        List<String> output = new ArrayList<>(entries.length);

        for (String e : entries) {
            if (e.startsWith("(") || e.endsWith(")")) {
                switch(e) {
                    case Signatures.HEADER_CREATED:
                    case Signatures.HEADER_REQUEST_TARGET:
                        break;

                    default:
                        throw new SignatureException("Invalid special field: " + e);
                }
            }

            if (e.contains("\"")) {
                throw new SignatureException("Invalid header name: " + e);
            }

            output.add(e);
        }

        return output;
    }

    protected Map<String, SigningAlgorithm> parseAlgorithms(String entry) throws SignatureException {
        String [] algoEntries = entry.split(",");
        Map<String, SigningAlgorithm> defaultAlgos = SigningAlgorithms.defaultAlgorithms();
        Map<String, SigningAlgorithm> algos = new HashMap<>();

        for (String a : algoEntries) {
            if (a.contains("=")) {
                String [] entries = a.split("=");
                if (entries.length != 2) {
                    throw new SignatureException("Invalid config entry: " + a);
                }

                // TODO Validate we can actually instantiate the cipher
                algos.put(entries[0], new SigningAlgorithm(entries[0], entries[1]));

            } else if (defaultAlgos.containsKey(a)) {
                algos.put(a, defaultAlgos.get(a));

            } else {
                throw new SignatureException("Could not find algorithm: " + a);
            }
        }

        return algos;
    }

    public HttpVerifier build() throws SignatureException {

        if (keyProvider == null) {
            throw new NullPointerException("keyProvider");
        }

        if (fieldList != null && fields != null) {
            throw new SignatureException("set only fieldList or fields, not both");
        }

        if (algorithmList != null && algorithms != null) {
            throw new SignatureException("set only algorithmList or algorithms, not both");
        }

        if (algorithmList != null) {
            algorithms = parseAlgorithms(algorithmList);
        } else if (algorithms == null) {
            algorithms = SigningAlgorithms.defaultAlgorithms();
        }

        if (fieldList != null) {
            fields = parseFieldList(fieldList);
        } else if (fields == null) {
            fields = Signatures.defaultFields();
        }

        if (headersToInclude == null) {
            headersToInclude = Signatures.defaultHeadersToInclude();
        }

        if (maxAge <= 0) {
            maxAge = DEFAULT_MAX_AGE_SEC;
        }

        if (clock == null) {
            clock = Clock.systemUTC();
        }

        Signatures signing = new Signatures(Signatures.DEFAULT_ALGORITHM, algorithms, fields, headersToInclude);

        return new HttpVerifierImpl(clock, signing, keyProvider, maxAge);
    }

}
