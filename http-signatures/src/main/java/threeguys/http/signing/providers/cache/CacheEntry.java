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

import java.security.Key;
import java.util.Objects;

public class CacheEntry<T extends Key> {

    private final String id;
    private final T key;
    private final long expires;

    public CacheEntry(String id, T key, long expires) {
        this.id = Objects.requireNonNull(id);
        this.key = Objects.requireNonNull(key);
        this.expires = expires;
    }

    public String getId() {
        return id;
    }

    public T getKey() {
        return key;
    }

    public long getExpires() {
        return expires;
    }

    public boolean isExpired(long currentTime) {
        return currentTime > getExpires();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CacheEntry that = (CacheEntry) o;
        return expires == that.expires &&
                id.equals(that.id) &&
                key.equals(that.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, key, expires);
    }

}
