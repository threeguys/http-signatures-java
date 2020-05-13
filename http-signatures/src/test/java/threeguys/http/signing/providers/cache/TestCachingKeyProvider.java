package threeguys.http.signing.providers.cache;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import threeguys.http.signing.exceptions.KeyNotFoundException;
import threeguys.http.signing.providers.MockKeys;

import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.time.Clock;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TestCachingKeyProvider {

    private KeyPair pair;
    private Clock clock;

    public TestCachingKeyProvider() throws NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        this.pair = MockKeys.newKeyPair();
        this.clock = Clock.fixed(Clock.systemUTC().instant(), ZoneId.of("UTC"));
    }

    private <T extends Key> KeyCache<T> mockCache(CacheEntry<T> entry) {
        KeyCache<T> cache = mock(KeyCache.class);
        when(cache.getEntry(any())).thenReturn(entry);
        return cache;
    }

    @Test
    public void happyCase() throws KeyNotFoundException {
        KeyCache<PublicKey> cache = mockCache(new CacheEntry<>("a-key", pair.getPublic(), clock.millis() + 1000));
        CachingKeyProvider<PublicKey> provider = new CachingKeyProvider<>(clock, cache, null);
        assertEquals(pair.getPublic(), provider.get("a-key"));
    }

    @Test
    public void expiredEntry_NoLoader() {
        KeyCache<PublicKey> cache = mockCache(new CacheEntry<>("b-key", pair.getPublic(), clock.millis() - 1000));
        CachingKeyProvider<PublicKey> provider = new CachingKeyProvider<>(clock, cache, null);
        assertThrows(KeyNotFoundException.class, () -> provider.get("b-key"));
        verify(cache, times(1)).getEntry(eq("b-key"));
        verify(cache, times(1)).invalidate(any());
    }

    @Test
    public void nullEntry_NoLoader() {
        KeyCache<PrivateKey> cache = mockCache(null);
        CachingKeyProvider<PrivateKey> provider = new CachingKeyProvider<>(clock, cache, null);
        assertThrows(KeyNotFoundException.class, () -> provider.get("c-key"));
        verify(cache, times(1)).getEntry(eq("c-key"));
    }

    @Test
    public void expiredEntry_WithLoader_NullLoad() throws KeyNotFoundException {
        KeyCache<PublicKey> cache = mockCache(new CacheEntry<>("d-key", pair.getPublic(), clock.millis() - 1000));
        CacheLoader<String, PublicKey> loader = mock(CacheLoader.class);
        when(loader.load(any())).thenReturn(null);

        CachingKeyProvider<PublicKey> provider = new CachingKeyProvider<>(clock, cache, loader);
        assertThrows(KeyNotFoundException.class, () -> provider.get("d-key"));
        verify(cache, times(1)).getEntry(eq("d-key"));
        verify(cache, times(1)).invalidate(any());
        verify(loader, times(1)).load(eq("d-key"));
    }

    @Test
    public void nullEntry_WithLoader_WithLoad() throws KeyNotFoundException {
        KeyCache<PublicKey> cache = mockCache(null);
        CacheLoader<String, PublicKey> loader = mock(CacheLoader.class);
        when(loader.load(any())).thenReturn(new CacheEntry<>("e-key", pair.getPublic(), clock.millis() + 2000));
        CachingKeyProvider<PublicKey> provider = new CachingKeyProvider<>(clock, cache, loader);

        PublicKey gotten = provider.get("e-key");
        assertEquals(gotten, pair.getPublic());
        verify(cache, times(1)).getEntry(eq("e-key"));
        verify(loader, times(1)).load(eq("e-key"));
    }

}
