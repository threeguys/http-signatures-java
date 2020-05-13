package threeguys.http.signing.providers.cache;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import threeguys.http.signing.providers.MockKeys;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestCacheEntry {

    private KeyPair pair;

    public TestCacheEntry() throws NoSuchProviderException, NoSuchAlgorithmException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        pair = MockKeys.newKeyPair("RSA", 2048);
    }

    @Test
    public void constructorAndProps() throws NoSuchProviderException, NoSuchAlgorithmException {
        CacheEntry<PrivateKey> ce = new CacheEntry<>("test", pair.getPrivate(), 1_000_000);

        assertEquals("test", ce.getId());
        assertEquals(pair.getPrivate(), ce.getKey());
        assertEquals(1_000_000, ce.getExpires());
        assertFalse(ce.isExpired(999_999));
        assertFalse(ce.isExpired(1_000_000));
        assertTrue(ce.isExpired(1_000_001));
    }

    @Test
    public void hashCodeEquals() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPair pair2 = MockKeys.newKeyPair("EC", 256);
        KeyPair pair3 = MockKeys.newKeyPair("RSA", 4096);

        List<CacheEntry<PublicKey>> entries = Arrays.asList(
                new CacheEntry<>("key-1", pair.getPublic(), 1_000),
                new CacheEntry<>("key-1", pair2.getPublic(), 1_000),
                new CacheEntry<>("key-1", pair.getPublic(), 999),
                new CacheEntry<>("key-2", pair3.getPublic(), 2_000),
                new CacheEntry<>("key-2", pair3.getPublic(), 1_999),
                new CacheEntry<>("key-2", pair.getPublic(), 2_000),
                new CacheEntry<>("key-3", pair3.getPublic(), 2_000)
        );

        for (CacheEntry<PublicKey> e1 : entries) {
            for (CacheEntry<PublicKey> e2 : entries) {
                if (System.identityHashCode(e1) == System.identityHashCode(e2)) {
                    assertTrue(e1.equals(e2));
                    assertTrue(e2.equals(e1));
                    assertEquals(e1.hashCode(), e2.hashCode());
                } else {
                    assertFalse(e1.equals(e2));
                    assertFalse(e2.equals(e1));
                    assertNotEquals(e1.hashCode(), e2.hashCode());
                }
            }
        }
    }

}
