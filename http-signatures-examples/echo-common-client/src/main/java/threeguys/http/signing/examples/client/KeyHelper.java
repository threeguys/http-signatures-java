/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

public class KeyHelper {

    byte[] readAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream baos= new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        for (int read=0; read != -1; read = in.read(buf)) { baos.write(buf, 0, read); }
        return baos.toByteArray();
    }

    private File getPublicKeyFile(String prefix) {
        return new File(prefix + ".public.pem");
    }

    public File getPrivateKeyFile(String prefix) {
        return new File(prefix + ".private.pem");
    }

    public byte [] loadPublicKeyPem(String prefix) throws IOException {
        File publicKeyFile = getPublicKeyFile(prefix);
        return readAllBytes(new FileInputStream(publicKeyFile));
    }

    public PrivateKey loadPrivateKey(String prefix) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());

        File publicKeyFile = getPublicKeyFile(prefix);
        File privateKeyFile = getPrivateKeyFile(prefix);
        boolean generateKeys = !publicKeyFile.exists() || !privateKeyFile.exists();

        if (generateKeys && (publicKeyFile.exists() || privateKeyFile.exists())) {
            throw new RuntimeException("Must have both or neither key file! Keys " + privateKeyFile.getName() + ":" + privateKeyFile.exists()
                    + ", " + publicKeyFile.getName() + ":" + publicKeyFile.exists() );
        }

        KeyPair pair;
        if (generateKeys) {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            keygen.initialize(new ECGenParameterSpec("secp192r1"), new SecureRandom());
            pair = keygen.generateKeyPair();

            JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(privateKeyFile));
            pw.writeObject(pair.getPrivate());
            pw.close();

            pw = new JcaPEMWriter(new FileWriter(publicKeyFile));
            pw.writeObject(pair.getPublic());
            pw.close();

        } else {
            PEMParser parser = new PEMParser(new FileReader(privateKeyFile));
            pair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) parser.readObject());
        }

        // We ignore the public key, just want to make sure it's a valid pair
        return pair.getPrivate();
    }

}
