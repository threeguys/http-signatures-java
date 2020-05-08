package threeguys.http.signing.algorithms;

import java.security.spec.MGF1ParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static java.security.spec.MGF1ParameterSpec.SHA256;
import static java.security.spec.MGF1ParameterSpec.SHA512;

public class SigningAlgorithms {

    public static final SigningAlgorithm RSA_SHA256 = new SigningAlgorithm("rsa-sha256", "SHA256withRSA");
    public static final SigningAlgorithm RSA_SHA284 = new SigningAlgorithm("rsa-sha384", "SHA384withRSA");
    public static final SigningAlgorithm RSA_SHA512 = new SigningAlgorithm("rsa-sha512", "SHA512withRSA");
    public static final SigningAlgorithm ECDSA_SHA256 = new SigningAlgorithm("ecdsa-sha256", "SHA256withECDSA");
    public static final SigningAlgorithm ECDSA_SHA384 = new SigningAlgorithm("ecdsa-sha384", "SHA384withECDSA");
    public static final SigningAlgorithm ECDSA_SHA512 = new SigningAlgorithm("ecdsa-sha512", "SHA512withECDSA");
    public static final SigningAlgorithm RSAPSS_SHA256 = new RsaPssAlgorithm("rsapss-sha256", "SHA-256", SHA256);
    public static final SigningAlgorithm RSAPSS_SHA512 = new RsaPssAlgorithm("rsapss-sha512", "SHA-512", SHA512);
    public static final SigningAlgorithm RSAPSS_SHA512_224 = new RsaPssAlgorithm("rsapss-sha512-224", "SHA-512/224",
                                                                                new MGF1ParameterSpec("SHA-512/224"));
    public static final SigningAlgorithm RSAPSS_SHA512_256 = new RsaPssAlgorithm("rsapss-sha512-256", "SHA-512/256",
                                                                                new MGF1ParameterSpec("SHA-512/256"));

    public static Map<String, SigningAlgorithm> defaultAlgorithms() {
        Map<String, SigningAlgorithm> algos = new HashMap<>();
        algos.put("rsa-sha256", RSA_SHA256);
        algos.put("rsa-sha384", RSA_SHA284);
        algos.put("rsa-sha512", RSA_SHA512);
        algos.put("ecdsa-sha256", ECDSA_SHA256);
        algos.put("ecdsa-sha384", ECDSA_SHA384);
        algos.put("ecdsa-sha512", ECDSA_SHA512);
        algos.put("rsapss-sha256", RSAPSS_SHA256);
        algos.put("rsapss-sha512", RSAPSS_SHA512);
        algos.put("rsapss-sha512-224", RSAPSS_SHA512_224);
        algos.put("rsapss-sha512-256", RSAPSS_SHA512_256);
        return Collections.unmodifiableMap(algos);
    }

}
