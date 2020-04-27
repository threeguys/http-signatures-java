package threeguys.http.signing;

import org.junit.Test;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class TestVerificationResult {

    @Test
    public void smokeTest() {

        PublicKey pk = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return null;
            }

            @Override
            public String getFormat() {
                return null;
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };

        Map<String, String> fields = new HashMap<>();
        fields.put(Signatures.FIELD_ALGORITHM, "test-algo");
        fields.put(Signatures.FIELD_KEY_ID, "test-key-id");

        VerificationResult r = new VerificationResult(pk, fields);
        assertEquals(pk, r.getKey());
        assertEquals("test-algo", r.getAlgorithm());
        assertEquals("test-key-id", r.getKeyId());
        assertEquals(fields, r.getFields());
    }

}
