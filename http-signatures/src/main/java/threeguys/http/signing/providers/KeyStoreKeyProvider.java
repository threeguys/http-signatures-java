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

import threeguys.http.signing.exceptions.KeyNotFoundException;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;

public class KeyStoreKeyProvider implements KeyProvider<PrivateKey> {

    private final KeyStore store;
    private final char [] password;

    public KeyStoreKeyProvider(KeyStore store, char [] password) {
        this.store = store;
        this.password = password.clone();
    }

    @Override
    public PrivateKey get(String name) throws KeyNotFoundException {
        Key key;
        try {
            key = store.getKey(name, password);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        if (key == null) {
            throw new KeyNotFoundException("Could not find key " + name);
        }

        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }

        throw new KeyNotFoundException("Found key but was not a PrivateKey");
    }

}
