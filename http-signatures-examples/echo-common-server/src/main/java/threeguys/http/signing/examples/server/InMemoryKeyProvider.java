/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.server;

import org.bouncycastle.util.io.pem.PemReader;
import threeguys.http.signing.exceptions.KeyNotFoundException;
import threeguys.http.signing.providers.KeyProvider;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class InMemoryKeyProvider implements KeyProvider<PublicKey> {

    public static final int MAX_IN_MEMORY_KEYS = 1000;
    private ReadWriteLock keysLock;
    private PublicKeyCache keys;

    public InMemoryKeyProvider() {
        this.keysLock = new ReentrantReadWriteLock();
        this.keys = new PublicKeyCache(MAX_IN_MEMORY_KEYS, MAX_IN_MEMORY_KEYS);
    }

    @Override
    public PublicKey get(String keyId) throws KeyNotFoundException {
        Lock lock = keysLock.readLock();
        lock.lock();
        PublicKey key = keys.get(keyId);
        lock.unlock();

        if (key == null) {
            throw new KeyNotFoundException("no key: " + keyId);
        }
        return key;
    }

    public void put(String keyId, PublicKey key) {
        Lock lock = keysLock.writeLock();
        lock.lock();
        keys.put(keyId, key);
        lock.unlock();
    }

    public void put(String keyId, String type, String pemData) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        put(keyId, readKey(type, pemData));
    }

    public PublicKey readKey(String type, String keyPem) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        byte [] keyData = new PemReader(new StringReader(keyPem)).readPemObject().getContent();
        KeyFactory keyFactory = KeyFactory.getInstance(type);
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyData));
    }

}
