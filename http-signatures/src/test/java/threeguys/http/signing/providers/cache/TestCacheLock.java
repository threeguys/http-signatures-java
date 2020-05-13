package threeguys.http.signing.providers.cache;

import org.junit.Test;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;

public class TestCacheLock {

    @Test
    public void happyCase_read() {
        Lock readLock = mock(Lock.class);
        Lock writeLock = mock(Lock.class);
        ReadWriteLock lock = mock(ReadWriteLock.class);
        when(lock.readLock()).thenReturn(readLock);
        when(lock.writeLock()).thenReturn(writeLock);

        CacheLock cl = new CacheLock(lock);
        try(CacheLock.Lock l = cl.reading()) {
            verify(readLock, times(1)).lock();
            verify(readLock, times(0)).unlock();
            verifyNoInteractions(writeLock);
        }

        verify(readLock, times(1)).unlock();
        verify(lock, times(1)).readLock();
        verifyNoInteractions(writeLock);
        verifyNoMoreInteractions(readLock, lock);
    }

    @Test
    public void happyCase_write() {
        Lock readLock = mock(Lock.class);
        Lock writeLock = mock(Lock.class);
        ReadWriteLock lock = mock(ReadWriteLock.class);
        when(lock.readLock()).thenReturn(readLock);
        when(lock.writeLock()).thenReturn(writeLock);

        CacheLock cl = new CacheLock(lock);
        try(CacheLock.Lock l = cl.writing()) {
            verify(writeLock, times(1)).lock();
            verify(writeLock, times(0)).unlock();
            verifyNoInteractions(readLock);
        }

        verify(writeLock, times(1)).unlock();
        verify(lock, times(1)).writeLock();
        verifyNoInteractions(readLock);
        verifyNoMoreInteractions(writeLock, lock);
    }

    @Test
    public void happyCase_normalLock() {
        CacheLock lock = new CacheLock();
        try(CacheLock.Lock l = lock.reading()) {
            assertNotNull(l);
        }

        try (CacheLock.Lock l = lock.writing()) {
            assertNotNull(l);
        }
    }

}
