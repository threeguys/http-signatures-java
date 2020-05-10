/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.server;

import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class ServerHelper {

    public PublicKey readKey(String type, String keyPem) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        byte [] keyData = new PemReader(new StringReader(keyPem)).readPemObject().getContent();
        KeyFactory keyFactory = KeyFactory.getInstance(type);
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyData));
    }



}
