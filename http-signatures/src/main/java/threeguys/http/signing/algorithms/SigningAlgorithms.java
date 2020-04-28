package threeguys.http.signing.algorithms;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static java.security.spec.MGF1ParameterSpec.SHA256;
import static java.security.spec.MGF1ParameterSpec.SHA512;

public class SigningAlgorithms {

    public static Map<String, SigningAlgorithm> defaultAlgorithms() {
        Map<String, SigningAlgorithm> algos = new HashMap<>();
        algos.put("rsa-sha256", new SigningAlgorithm("rsa-sha256", "SHA256withRSA"));
        algos.put("rsa-sha384", new SigningAlgorithm("rsa-sha384", "SHA384withRSA"));
        algos.put("rsa-sha512", new SigningAlgorithm("rsa-sha512", "SHA512withRSA"));
        algos.put("ecdsa-sha256", new SigningAlgorithm("ecdsa-sha256", "SHA256withECDSA"));
        algos.put("ecdsa-sha384", new SigningAlgorithm("ecdsa-sha384", "SHA384withECDSA"));
        algos.put("ecdsa-sha512", new SigningAlgorithm("ecdsa-sha512", "SHA512withECDSA"));
        algos.put("rsapss-sha256", new RsaPssAlgorithm("rsapss-sha256", "SHA-256", SHA256));
        algos.put("rsapss-sha512", new RsaPssAlgorithm("rsapss-sha512", "SHA-512", SHA512));
        return Collections.unmodifiableMap(algos);
    }

}
