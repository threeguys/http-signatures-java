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
package threeguys.http.signing.config;

import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.HttpVerifierImpl;
import threeguys.http.signing.RequestSigning;
import threeguys.http.signing.exceptions.KeyNotFoundException;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.providers.KeyProvider;
import threeguys.http.signing.providers.PublicKeyStoreProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpVerifierBuilder {

    public static final int DEFAULT_MAX_AGE_SEC = 300;

    private Map<String, String> algorithms;
    private String algorithmList;
    private List<String> fields;
    private String fieldList;
    private char [] keystorePassword;
    private String keystoreType;
    private String keystorePath;
    private int maxAge = -1;

    public HttpVerifierBuilder withAlgorithms(Map<String, String> algorithms) {
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

    public HttpVerifierBuilder withKeystorePassword(char [] keystorePassword) {
        this.keystorePassword = keystorePassword;
        return this;
    }

    public HttpVerifierBuilder withKeystorePassword(String keystorePassword) {
        return withKeystorePassword(keystorePassword.toCharArray());
    }

    public HttpVerifierBuilder withKeystorePath(String keystorePath) {
        this.keystorePath = keystorePath;
        return this;
    }

    public HttpVerifierBuilder withKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
        return this;
    }

    public HttpVerifierBuilder withMaxAge(int maxAge) {
        this.maxAge = maxAge;
        return this;
    }

    public HttpVerifierBuilder withMaxAge(String maxAge) {
        return withMaxAge(Integer.parseInt(maxAge));
    }

    public static KeyStore loadKeyStore(String storeType, String path, char [] password) throws KeyNotFoundException {
        String useStoreType = storeType == null ? KeyStore.getDefaultType() : storeType;

        if (path == null) {
            throw new KeyNotFoundException("keystore parameter is required");
        }

        try {
            KeyStore keyStore = KeyStore.getInstance(useStoreType);

            InputStream input;
            if (path.startsWith("classpath:")) {
                input = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
            } else {
                input = new FileInputStream(path);
            }

            keyStore.load(input, password);
            return keyStore;

        } catch (KeyStoreException | IOException
                | CertificateException | NoSuchAlgorithmException e) {
            throw new KeyNotFoundException(e);
        }
    }

    public static List<String> parseFieldList(String entry) throws SignatureException {
        String [] entries = entry.split(",");
        List<String> output = new ArrayList<>(entries.length);

        for (String e : entries) {
            if (e.startsWith("(") || e.endsWith(")")) {
                switch(e) {
                    case RequestSigning.HEADER_CREATED:
                    case RequestSigning.HEADER_REQUEST_TARGET:
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

    protected Map<String, String> parseAlgorithms(String entry) throws SignatureException {
        String [] algoEntries = entry.split(",");
        Map<String, String> defaultAlgos = RequestSigning.defaultAlgorithms();
        Map<String, String> algos = new HashMap<>();

        for (String a : algoEntries) {
            if (a.contains("=")) {
                String [] entries = a.split("=");
                if (entries.length != 2) {
                    throw new SignatureException("Invalid config entry: " + a);
                }

                // TODO Validate we can actually instantiate the cipher
                algos.put(entries[0], entries[1]);

            } else if (defaultAlgos.containsKey(a)) {
                algos.put(a, defaultAlgos.get(a));

            } else {
                throw new SignatureException("Could not find algorithm: " + a);
            }
        }

        return algos;
    }

    public HttpVerifier build() throws SignatureException {

        if (keystorePath == null) {
            throw new KeyNotFoundException("keystorePath is required");
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
            algorithms = RequestSigning.defaultAlgorithms();
        }

        if (fieldList != null) {
            fields = parseFieldList(fieldList);
        } else if (fields == null) {
            fields = RequestSigning.defaultFields();
        }

        if (keystoreType == null) {
            keystoreType = KeyStore.getDefaultType();
        }

        if (keystorePassword == null) {
            keystorePassword = new char[]{};
        }

        if (maxAge <= 0) {
            maxAge = DEFAULT_MAX_AGE_SEC;
        }

        RequestSigning signing = new RequestSigning(algorithms, fields);

        KeyStore keyStore = loadKeyStore(keystoreType, keystorePath, keystorePassword);
        KeyProvider<PublicKey> keyProvider = new PublicKeyStoreProvider(keyStore, keystorePassword);

        return new HttpVerifierImpl(signing, keyProvider, maxAge);
    }

}
