package threeguys.http.signing.providers.cache;

import threeguys.http.signing.providers.KeyProvider;

import java.security.Key;
import java.time.Clock;

public class ConcurrentInMemoryLruKeyCache<T extends Key> implements KeyProvider<T>, KeyCache<T> {

    private final Clock clock;
    private final LruKeyHashMap<T> cache;
    private final CacheLock lock;

    public ConcurrentInMemoryLruKeyCache(int maxEntries) {
        this(Clock.systemUTC(), new LruKeyHashMap<>((maxEntries > 0) ? maxEntries : 1000), new CacheLock());
    }

    public ConcurrentInMemoryLruKeyCache(Clock clock, LruKeyHashMap<T> cache, CacheLock lock) {
        this.clock = clock;
        this.cache = cache;
        this.lock = lock;
    }

    @Override
    public T get(String name) {
        CacheEntry<T> entry;
        try (CacheLock.Lock l = lock.reading()) {
            entry = cache.get(name);
        }

        if (entry != null) {
            long time = clock.millis();
            if (entry.isExpired(time)) {

                try (CacheLock.Lock l = lock.writing()) {
                    entry = cache.removeIfExpired(entry.getId(), time);
                    if (entry != null) {
                        return entry.getKey();
                    }
                }

            } else {
                return entry.getKey();
            }
        }
        return null;
    }

    @Override
    public CacheEntry<T> getEntry(String keyId) {
        try (CacheLock.Lock l = lock.reading()) {
            return cache.get(keyId);
        }
    }

    @Override
    public CacheEntry<T> putEntry(CacheEntry<T> entry) {
        try (CacheLock.Lock l = lock.writing()) {
            return cache.put(entry.getId(), entry);
        }
    }

    @Override
    public CacheEntry<T> invalidate(CacheEntry<T> entry) {
        try (CacheLock.Lock l = lock.writing()) {
            return cache.invalidate(entry);
        }
    }

}
