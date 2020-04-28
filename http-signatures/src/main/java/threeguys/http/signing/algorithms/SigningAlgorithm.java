package threeguys.http.signing.algorithms;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SigningAlgorithm {

    private final String identifier;
    private final String algorithm;
    private final String provider;

    public SigningAlgorithm(String identifier, String algorithm) {
        this(identifier, algorithm, null);
    }

    public SigningAlgorithm(String identifier, String algorithm, String provider) {
        this.identifier = identifier;
        this.algorithm = algorithm;
        this.provider = provider;
    }

    public Signature create() throws GeneralSecurityException {
        return (provider == null) ? Signature.getInstance(algorithm)
                : Signature.getInstance(algorithm, provider);
    }

    public Signature verifier(PublicKey key) throws GeneralSecurityException {
        Signature signature = create();
        signature.initVerify(key);
        return signature;
    }

    public Signature signer(PrivateKey key) throws GeneralSecurityException {
        Signature signature = create();
        signature.initSign(key);
        return signature;
    }

}
