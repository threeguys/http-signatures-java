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
