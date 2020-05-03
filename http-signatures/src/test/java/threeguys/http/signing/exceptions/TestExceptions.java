package threeguys.http.signing.exceptions;

import org.junit.Test;

import static org.junit.Assert.*;

public class TestExceptions {

    private void checkException(String exectedMessage,Exception ex) throws Exception {
        assertEquals(exectedMessage, ex.getMessage());
        throw ex;
    }

    @Test(expected = ExpiredSignatureException.class)
    public void expiredSignatureException() throws Exception {
        checkException("test-message", new ExpiredSignatureException("test-message"));
    }

    @Test(expected = InvalidFieldException.class)
    public void invalidFieldException() throws Exception {
        checkException("test-message-2", new InvalidFieldException("test-message-2"));
    }

    @Test(expected = InvalidSignatureException.class)
    public void invalidSignatureException() throws Exception {
        Exception ex = new RuntimeException();
        assertEquals(ex, new InvalidSignatureException(ex).getCause());
        assertEquals("dude", new InvalidSignatureException("dude", ex).getMessage());
        assertEquals(ex, new InvalidSignatureException("dude", ex).getCause());
        checkException("test-message-3", new InvalidSignatureException("test-message-3"));
    }

    @Test(expected = KeyNotFoundException.class)
    public void keyNotFoundException() throws Exception {
        Exception ex = new IllegalArgumentException();
        assertEquals(ex, new KeyNotFoundException(ex).getCause());
        checkException("test-message-4", new KeyNotFoundException("test-message-4"));
    }

    @Test(expected = MissingHeadersException.class)
    public void missingHeadersException() throws Exception {
        Exception ex = new IllegalStateException();
        assertEquals(ex, new MissingHeadersException(ex).getCause());
        checkException("test-message-5", new MissingHeadersException("test-message-5"));
    }

    @Test(expected = SignatureException.class)
    public void signatureException() throws Exception {
        Exception ex = new IllegalAccessException();
        assertEquals(ex, new SignatureException(ex).getCause());
        assertEquals(ex, new SignatureException("test", ex).getCause());
        assertEquals("test-2", new SignatureException("test-2", ex).getMessage());
        checkException("test-message-6", new SignatureException("test-message-6"));
    }


}
