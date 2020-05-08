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

import java.security.PublicKey;
import java.util.Map;

import static threeguys.http.signing.Signatures.*;

public class VerificationResult {

    private final Map<String, String> fields;
    private final PublicKey key;
    private final String algorithm;

    public VerificationResult(PublicKey key, Map<String, String> fields) {
        this(key, fields.get(FIELD_ALGORITHM), fields);
    }

    public VerificationResult(PublicKey key, String algorithm, Map<String, String> fields) {
        this.key = key;
        this.algorithm = algorithm;
        this.fields = fields;
    }

    public PublicKey getKey() {
        return key;
    }

    public Map<String, String> getFields() {
        return fields;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getKeyId() {
        return fields.get(FIELD_KEY_ID);
    }

}
