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
package threeguys.http.signing.spring;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.RequestSigning;
import threeguys.http.signing.VerificationResult;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.providers.HeaderProvider;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static threeguys.http.signing.RequestSigning.*;

public class TestHttpSignatureFilter {

    private static class MockRequestSigning extends RequestSigning {

    }

    private static class MockHttpVerifier extends HttpVerifier  {

        private VerificationResult result;
        private SignatureException exception;

        public MockHttpVerifier(VerificationResult result, SignatureException exception) {
            super(new MockRequestSigning(), (name) -> new MockPublicKey());
            this.result = result;
            this.exception = exception;
        }

        @Override
        public VerificationResult verify(String method, String url, HeaderProvider provider) throws SignatureException {
            if (exception != null) {
                throw exception;
            }
            return result;
        }

    }

    @Test
    public void happyCase() throws IOException, ServletException {
        Map<String, String> fields = new HashMap<>();
        fields.put(FIELD_ALGORITHM, "test-algo");
        fields.put(FIELD_KEY_ID, "test-key-id");

        MockPublicKey key = new MockPublicKey();
        MockHttpVerifier verifier = new MockHttpVerifier(new VerificationResult(key, fields), null);
        HttpSignatureFilter filter = new HttpSignatureFilter(new MockRequestMatcher(), verifier);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication obj = filter.attemptAuthentication(request, response);
        assertTrue(obj instanceof HttpSignatureToken);
        HttpSignatureToken auth = (HttpSignatureToken) obj;

        assertEquals("test-algo", auth.getAlgorithm());
        assertEquals("test-key-id", auth.getKeyId());
        assertEquals(key, auth.getCredentials());

        HttpSignatureUser user = (HttpSignatureUser) auth.getPrincipal();
        assertEquals("test-key-id", user.getName());
    }

    @Test(expected = HttpSignatureAuthenticationException.class)
    public void invalidKeyError() throws IOException, ServletException {
        MockHttpVerifier verifier = new MockHttpVerifier(null, new InvalidSignatureException("this-is-a-test"));
        HttpSignatureFilter filter = new HttpSignatureFilter(new MockRequestMatcher(), verifier);
        filter.attemptAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test(expected = ServletException.class)
    public void genericError() throws IOException, ServletException {
        MockHttpVerifier verifier = new MockHttpVerifier(null, new SignatureException("this-is-a-test"));
        HttpSignatureFilter filter = new HttpSignatureFilter(new MockRequestMatcher(), verifier);
        filter.attemptAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse());
    }

}
