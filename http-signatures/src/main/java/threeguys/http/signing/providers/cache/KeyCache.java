package threeguys.http.signing.providers.cache;

import java.security.Key;

public interface KeyCache<T extends Key> {

    CacheEntry<T> getEntry(String keyId);
    CacheEntry<T> putEntry(CacheEntry<T> entry);
    CacheEntry<T> invalidate(CacheEntry<T> entry);

}
