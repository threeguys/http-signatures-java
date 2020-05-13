/**
 *    Copyright 2020 Ray Cole
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package threeguys.http.signing.exceptions;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TestExceptions {

    private void checkException(String exectedMessage,Exception ex) throws Exception {
        assertEquals(exectedMessage, ex.getMessage());
        throw ex;
    }

    @Test
    public void expiredSignatureException() {
        assertThrows(ExpiredSignatureException.class,
                () -> checkException("test-message", new ExpiredSignatureException("test-message")));
    }

    @Test
    public void invalidFieldException() {
        assertThrows(InvalidFieldException.class,
                () -> checkException("test-message-2", new InvalidFieldException("test-message-2")));
    }

    @Test
    public void invalidSignatureException() {
        Exception ex = new RuntimeException();
        assertEquals(ex, new InvalidSignatureException(ex).getCause());
        assertEquals("dude", new InvalidSignatureException("dude", ex).getMessage());
        assertEquals(ex, new InvalidSignatureException("dude", ex).getCause());
        assertThrows(InvalidSignatureException.class,
                () -> checkException("test-message-3", new InvalidSignatureException("test-message-3")));
    }

    @Test
    public void keyNotFoundException() {
        Exception ex = new IllegalArgumentException();
        assertEquals(ex, new KeyNotFoundException(ex).getCause());
        assertEquals("here's your message", new KeyNotFoundException("here's your message", null).getMessage());
        assertEquals(ex, new KeyNotFoundException("test", ex).getCause());
        assertThrows(KeyNotFoundException.class,
                () -> checkException("test-message-4", new KeyNotFoundException("test-message-4")));
    }

    @Test
    public void missingHeadersException() {
        Exception ex = new IllegalStateException();
        assertEquals(ex, new MissingHeadersException(ex).getCause());
        assertThrows(MissingHeadersException.class,
                () -> checkException("test-message-5", new MissingHeadersException("test-message-5")));
    }

    @Test
    public void signatureException() {
        Exception ex = new IllegalAccessException();
        assertEquals(ex, new SignatureException(ex).getCause());
        assertEquals(ex, new SignatureException("test", ex).getCause());
        assertEquals("test-2", new SignatureException("test-2", ex).getMessage());
        assertThrows(SignatureException.class,
                () -> checkException("test-message-6", new SignatureException("test-message-6")));
    }

}
