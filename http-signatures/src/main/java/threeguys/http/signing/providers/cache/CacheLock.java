package threeguys.http.signing.providers.cache;

import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class CacheLock {

    private final ReadWriteLock cacheLock;

    public static class Lock implements AutoCloseable {

        private final java.util.concurrent.locks.Lock theLock;

        public Lock(java.util.concurrent.locks.Lock theLock) {
            this.theLock = theLock;
            this.theLock.lock();
        }

        @Override
        public void close() {
            this.theLock.unlock();
        }

    }

    public CacheLock() {
        this(new ReentrantReadWriteLock());
    }

    public CacheLock(ReadWriteLock cacheLock) {
        this.cacheLock = cacheLock;
    }

    public Lock reading() {
        return new Lock(cacheLock.readLock());
    }

    public Lock writing() {
        return new Lock(cacheLock.writeLock());
    }

}
