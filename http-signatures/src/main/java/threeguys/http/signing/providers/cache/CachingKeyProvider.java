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
package threeguys.http.signing.providers.cache;

import threeguys.http.signing.exceptions.KeyNotFoundException;
import threeguys.http.signing.providers.KeyProvider;

import java.security.Key;
import java.time.Clock;

public class CachingKeyProvider<T extends Key> implements KeyProvider<T> {

    private final Clock clock;
    private final KeyCache<T> cache;
    private final CacheLoader<String, T> loader;

    public CachingKeyProvider(Clock clock, KeyCache<T> cache, CacheLoader<String, T> loader) {
        this.clock = clock;
        this.cache = cache;
        this.loader = loader;
    }

    @Override
    public T get(String keyId) throws KeyNotFoundException {
        CacheEntry<T> ce = cache.getEntry(keyId);
        if (ce != null && !ce.isExpired(clock.millis())) {
            return ce.getKey();
        }

        if (ce != null) {
            cache.invalidate(ce);
        }

        if (loader != null) {
            ce = loader.load(keyId);
            if (ce != null) {
                cache.putEntry(ce);
                return ce.getKey();
            }
        }

        throw new KeyNotFoundException("Key " + keyId);
    }

}
