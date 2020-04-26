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
import threeguys.http.signing.VerificationResult;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.mocks.MockHttpVerifier;
import threeguys.http.signing.servlet.HttpSignatureVerifierFilter;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static threeguys.http.signing.RequestSigning.FIELD_ALGORITHM;
import static threeguys.http.signing.RequestSigning.FIELD_KEY_ID;

public class TestHttpHandlerSecurityInterceptor {

    @Test
    public void happyCase() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put(FIELD_ALGORITHM, "test-algo");
        fields.put(FIELD_KEY_ID, "test-key-id");

        MockPublicKey key = new MockPublicKey();
        MockHttpVerifier verifier = new MockHttpVerifier(new VerificationResult(key, fields), null);
        HttpSignatureHandlerInterceptor filter = new HttpSignatureHandlerInterceptor(new HttpSignatureVerifierFilter(verifier));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.preHandle(request, response, null);
    }

    @Test
    public void invalidKeyError() throws Exception {
        MockHttpVerifier verifier = new MockHttpVerifier(null, new InvalidSignatureException("this-is-a-test"));
        HttpSignatureHandlerInterceptor filter = new HttpSignatureHandlerInterceptor(new HttpSignatureVerifierFilter(verifier));
        assertFalse(filter.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), null));
    }

    @Test
    public void genericError() throws Exception {
        MockHttpVerifier verifier = new MockHttpVerifier(null, new SignatureException("this-is-a-test"));
        HttpSignatureHandlerInterceptor filter = new HttpSignatureHandlerInterceptor(new HttpSignatureVerifierFilter(verifier));
        assertFalse(filter.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), null));
    }

}
