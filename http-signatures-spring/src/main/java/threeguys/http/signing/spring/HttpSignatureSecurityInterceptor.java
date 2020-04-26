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

import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.servlet.HttpSigningServletFilter;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class HttpSignatureFilter extends FilterSecurityInterceptor {

    private HttpVerifier verifier;
    private HttpSigningServletFilter filter;

    protected HttpSignatureFilter(HttpVerifier verifier) {
        super();
        this.verifier = verifier;
        this.filter = new HttpSigningServletFilter();
    }

    @Override
    public void init(FilterConfig config) {
        super.init(config);
        try {
            filter.init(config);
        } catch (ServletException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        filter.doFilter(request, response, chain);
    }

    @Override
    public void destroy() {
        super.destroy();
        filter.destroy();
    }

}
