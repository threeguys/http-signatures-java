package threeguys.http.signing.algorithms;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RsaPssAlgorithm extends SigningAlgorithm {

    public static final String ALGORITHM = "RSASSA-PSS";
    public static final String MASK_FUNCTION = "MGF1";
    public static final int SALT_LENGTH = 0;
    public static final int TRAILER_FIELD = 1;

    private final String hashName;
    private final AlgorithmParameterSpec hashSpec;

    @Override
    public Signature create() throws GeneralSecurityException {
        Signature signature = super.create();
        signature.setParameter(new PSSParameterSpec(hashName, MASK_FUNCTION, hashSpec, SALT_LENGTH, TRAILER_FIELD));
        return signature;
    }

    public RsaPssAlgorithm(String identifier, String hashName, AlgorithmParameterSpec hashSpec) {
        super(identifier, ALGORITHM);
        this.hashName = hashName;
        this.hashSpec = hashSpec;
    }

}
