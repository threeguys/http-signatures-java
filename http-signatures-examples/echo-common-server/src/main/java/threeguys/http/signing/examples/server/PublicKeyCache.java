/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.server;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

public class PublicKeyCache extends LinkedHashMap<String, PublicKey> {

    private final int maxEntries;

    public PublicKeyCache(int initialCapacity, int maxEntries) {
        super(initialCapacity, 0.75f, true);
        this.maxEntries = maxEntries;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<String, PublicKey> eldest) {
        return size() > maxEntries;
    }

}
