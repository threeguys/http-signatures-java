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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.exceptions.KeyNotFoundException;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.servlet.HttpServletRequestHeaderProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HttpSignatureHandlerInterceptor extends HandlerInterceptorAdapter {

    private static final Log log = LogFactory.getLog(HttpSignatureHandlerInterceptor.class);
    private HttpVerifier verifier;

    public HttpSignatureHandlerInterceptor(HttpVerifier verifier) {
        super();
        this.verifier = verifier;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        try {
            verifier.verify(request.getMethod(), request.getRequestURI(), new HttpServletRequestHeaderProvider(request));
        } catch (InvalidSignatureException | KeyNotFoundException e) {
            log.warn("Unauthorized request: " + request.getSession().getId(), e);
            response.sendError(401, "Not Authorized");
            return false;

        } catch (SignatureException e) {
            log.error("Error verifying request", e);
            return false;
        }

        return true;
    }

}
