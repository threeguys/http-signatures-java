package threeguys.http.signing.providers.cache;

import threeguys.http.signing.exceptions.KeyNotFoundException;

import java.nio.ByteBuffer;
import java.security.Key;
import java.time.Clock;

public abstract class AbstractCacheLoader<T extends Key> implements CacheLoader<String, T> {

    private final Clock clock;
    private final long timeoutMs;

    public AbstractCacheLoader(Clock clock, long timeoutSecs) {
        this.clock = clock;
        this.timeoutMs = timeoutSecs * 1000;
    }

    public Clock getClock() {
        return clock;
    }

    public long nextExpires() {
        return clock.millis() + timeoutMs;
    }

    protected abstract ByteBuffer loadResource(String keyId) throws KeyNotFoundException;
    protected abstract CacheEntry<T> convertToEntry(String keyId, ByteBuffer buffer) throws KeyNotFoundException;

    @Override
    public CacheEntry<T> load(String keyId) throws KeyNotFoundException {
        ByteBuffer buffer = loadResource(keyId);
        if (buffer == null) {
            throw new KeyNotFoundException("No data for key: " + keyId);
        }

        return convertToEntry(keyId, buffer);
    }

}
