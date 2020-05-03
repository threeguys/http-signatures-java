package threeguys.http.signing.algorithms;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Objects;

public class SigningAlgorithm {

    private final String identifier;
    private final String algorithm;
    private final String provider;

    public SigningAlgorithm(String identifier, String algorithm) {
        this(identifier, algorithm, null);
    }

    public SigningAlgorithm(String identifier, String algorithm, String provider) {
        if (algorithm == null || identifier == null) {
            throw new NullPointerException();
        }
        this.identifier = identifier;
        this.algorithm = algorithm;
        this.provider = provider;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getProvider() {
        return provider;
    }

    public String getName() {
        return getIdentifier() + "/" + getAlgorithm() + "/" + getProvider();
    }


    public Signature create() throws GeneralSecurityException {
        return (provider == null) ? Signature.getInstance(algorithm)
                : Signature.getInstance(algorithm, provider);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigningAlgorithm that = (SigningAlgorithm) o;
        return identifier.equals(that.identifier) &&
                algorithm.equals(that.algorithm) &&
                Objects.equals(provider, that.provider);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identifier, algorithm, provider);
    }

}
