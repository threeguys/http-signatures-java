package threeguys.http.signing;

import java.security.PublicKey;
import java.util.Map;

import static threeguys.http.signing.RequestSigning.*;

public class VerificationResult {

    private final Map<String, String> fields;
    private final PublicKey key;

    public VerificationResult(PublicKey key, Map<String, String> fields) {
        this.key = key;
        this.fields = fields;
    }

    public PublicKey getKey() {
        return key;
    }

    public Map<String, String> getFields() {
        return fields;
    }

    public String getAlgorithm() {
        return fields.get(FIELD_ALGORITHM);
    }

    public String getKeyId() {
        return fields.get(FIELD_KEY_ID);
    }

}
