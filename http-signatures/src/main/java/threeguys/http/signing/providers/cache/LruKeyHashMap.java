package threeguys.http.signing.providers.cache;

import java.security.Key;
import java.util.LinkedHashMap;
import java.util.Map;

public class LruKeyHashMap<T extends Key>  extends LinkedHashMap<String, CacheEntry<T>> {

    private final int maxEntries;

    public LruKeyHashMap(int maxEntries) {
        super((maxEntries >> 1) + 1, 0.75f, true);
        this.maxEntries = maxEntries;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<String, CacheEntry<T>> eldest) {
        return size() > maxEntries;
    }

    public CacheEntry<T> removeIfExpired(String id, long currentTime) {
        CacheEntry<T> suspect = super.get(id);
        if (suspect != null && suspect.getExpires() < currentTime) {
            super.remove(id);
            return null;
        }
        return suspect;
    }

    public CacheEntry<T> invalidate(CacheEntry<T> entry) {
        String id = entry.getId();
        CacheEntry<T> suspect = super.get(id);
        if (entry.equals(suspect)) {
            super.remove(id);
            return null;
        }
        return suspect;
    }

}
