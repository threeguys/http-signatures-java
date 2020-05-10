/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.server;

import threeguys.http.signing.exceptions.KeyNotFoundException;
import threeguys.http.signing.providers.KeyProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
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

    public KeyPair newKeyPair(String keyId) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecSpec, new SecureRandom());
        KeyPair kp = generator.generateKeyPair();
        keys.put(keyId, kp.getPublic());
        return kp;
    }

}
