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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.VerificationResult;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.exceptions.SignatureException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class HttpSignatureFilter extends AbstractAuthenticationProcessingFilter {

    private HttpVerifier verifier;

    protected HttpSignatureFilter(RequestMatcher matcher, HttpVerifier verifier) {
        super(matcher);
        this.verifier = verifier;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        try {
            VerificationResult result = verifier.verify(request.getMethod(), request.getPathInfo(), new HttpServletRequestProvider(request));
            HttpSignatureUser user = new HttpSignatureUser(result.getKeyId());
            return new HttpSignatureToken(user, result.getAlgorithm(), result.getKeyId(), result.getKey(), Collections.emptyList());
        } catch(InvalidSignatureException e) {
            throw new HttpSignatureAuthenticationException("Could not authenticate", e);
        } catch (SignatureException e) {
            throw new ServletException(e);
        }
    }

}
