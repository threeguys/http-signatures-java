package threeguys.http.signing.providers.cache;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import threeguys.http.signing.providers.MockKeys;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.time.Clock;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.*;

public class TestLruKeyHashMap {

    private final Clock clock;
    private KeyPair pair;

    public TestLruKeyHashMap() throws NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        this.clock = Clock.fixed(Clock.systemUTC().instant(), ZoneId.of("UTC"));
        this.pair = MockKeys.newKeyPair();
    }

    @Test
    public void happyCase() throws NoSuchProviderException, NoSuchAlgorithmException {
        LruKeyHashMap<PublicKey> map = new LruKeyHashMap<>(5);

        for (int i=1; i<6; i++) {
            map.put(Integer.toString(i), new CacheEntry<>(Integer.toString(i),
                    MockKeys.newKeyPair().getPublic(), clock.millis() + (i * 1000)));
        }

        assertEquals(5, map.size());

        CacheEntry<PublicKey> tmp = new CacheEntry<>("yo", MockKeys.newKeyPair().getPublic(), clock.millis() + 10000);
        map.put("yo", new CacheEntry<>("yo", tmp.getKey(), clock.millis() + 10000));
        assertEquals(5, map.size());
        assertEquals(tmp, map.get("yo"));

        map.invalidate(tmp);
        assertEquals(4, map.size());
        map.put("dude", new CacheEntry<>("dude", MockKeys.newKeyPair().getPublic(), clock.millis() + 20000));
        assertFalse(map.containsKey("yo"));
        assertTrue(map.containsKey("dude"));
        assertEquals(5, map.size());
    }

    @Test
    public void invalidate_staleData() {
        LruKeyHashMap<PublicKey> map = new LruKeyHashMap<>(10);
        map.put("test", new CacheEntry<>("test", pair.getPublic(), clock.millis() + 10000));

        CacheEntry<PublicKey> found = map.invalidate(new CacheEntry<>("test", pair.getPublic(), clock.millis()));
        assertEquals(found, map.get("test"));
        assertEquals(1, map.size());
    }

    @Test
    public void removeIfExpired_happyCase() {
        LruKeyHashMap<PublicKey> map = new LruKeyHashMap<>(20);
        map.put("expired", new CacheEntry<>("expired", pair.getPublic(), clock.millis() - 1000));
        assertNull(map.removeIfExpired("expired", clock.millis()));
        assertEquals(0, map.size());
    }

    @Test
    public void removeIfExpired_notExpired() {
        LruKeyHashMap<PublicKey> map = new LruKeyHashMap<>(20);
        map.put("not-expired", new CacheEntry<>("not-expired", pair.getPublic(), clock.millis() + 1000));
        assertEquals(map.get("not-expired"), map.removeIfExpired("not-expired", clock.millis()));
        assertEquals(1, map.size());
    }

    @Test
    public void removeIfExpired_entryMissing() {
        LruKeyHashMap<PublicKey> map = new LruKeyHashMap<>(20);
        assertNull(map.removeIfExpired("not-existing", clock.millis()));
    }

}
