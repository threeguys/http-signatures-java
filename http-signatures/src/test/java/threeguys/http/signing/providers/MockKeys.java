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
package threeguys.http.signing.providers;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import threeguys.http.signing.exceptions.KeyNotFoundException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class MockKeys {

    public static final String DEFAULT_PASSWORD = "mock-keys-password";

    public static KeyStore emptyStore(String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, password.toCharArray());
        return keyStore;
    }

    public static KeyStore emptyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return emptyStore(DEFAULT_PASSWORD);
    }

    public static File saveStore(KeyStore ks, File out, String password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        try (FileOutputStream fos = new FileOutputStream(out)) {
            ks.store(fos, password.toCharArray());
        }
        return out;
    }

    public static File saveStore(KeyStore ks, File out) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return saveStore(ks, out, DEFAULT_PASSWORD);
    }

    public static X509Certificate newCertificate(KeyPair keyPair) throws OperatorCreationException, IOException, CertificateException, NoSuchProviderException {
        Date notBefore = Date.from(Instant.now().minus(Duration.ofMinutes(10)));
        Date expires = Date.from(Instant.now().plus(Duration.ofHours(1)));

        String algoName = "SHA256WithRSA";
        AlgorithmIdentifier algoId = new DefaultSignatureAlgorithmIdentifierFinder().find(algoName);
        AlgorithmIdentifier digestId = new DefaultDigestAlgorithmIdentifierFinder().find(algoId);

        SubjectPublicKeyInfo subjectKey = new SubjectPublicKeyInfo(algoId, keyPair.getPublic().getEncoded());
        AuthorityKeyIdentifier authKey = new AuthorityKeyIdentifier(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name("CN=unit-test"),
                BigInteger.ONE,
                new Time(notBefore, Locale.US), new Time(expires, Locale.US),
                new X500Name("CN=unit-test"),
                subjectKey);

        builder
                .addExtension(Extension.subjectKeyIdentifier, false, subjectKey)
                .addExtension(Extension.authorityKeyIdentifier, false, authKey)
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA")
                                                .build(keyPair.getPrivate());

        X509CertificateHolder holder = builder.build(contentSigner);
        ByteArrayInputStream bis = new ByteArrayInputStream(holder.toASN1Structure().getEncoded());
        CertificateFactory factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) factory.generateCertificate(bis);
    }

    public static KeyPair newKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kp = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        kp.initialize(keySize);
        return kp.generateKeyPair();
    }

    public static KeyStore loadKeyStore(String storeType, String path, char [] password) throws KeyNotFoundException {
        String useStoreType = storeType == null ? KeyStore.getDefaultType() : storeType;

        if (path == null) {
            throw new KeyNotFoundException("keystore parameter is required");
        }

        try {
            KeyStore keyStore = KeyStore.getInstance(useStoreType);

            InputStream input;
            if (path.startsWith("classpath:")) {
                input = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
            } else {
                input = new FileInputStream(path);
            }

            keyStore.load(input, password);
            return keyStore;

        } catch (KeyStoreException | IOException
                | CertificateException | NoSuchAlgorithmException e) {
            throw new KeyNotFoundException(e);
        }
    }

    public static KeyPair newKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        return newKeyPair("RSA", 1024);
    }

    public static PublicKey classpathPublicKey(String name) throws IOException {
        InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(name);
        PEMParser parser = new PEMParser(new InputStreamReader(stream));

        Object obj = parser.readObject();
        assertTrue(obj instanceof SubjectPublicKeyInfo);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return converter.getPublicKey((SubjectPublicKeyInfo) obj);
    }

    public static PrivateKey classpathPrivateKey(String name) throws IOException {
        InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(name);
        PEMParser parser = new PEMParser(new InputStreamReader(stream));

        Object obj = parser.readObject();
        assertTrue(obj instanceof PEMKeyPair);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return converter.getPrivateKey(((PEMKeyPair) obj).getPrivateKeyInfo());
    }

}
