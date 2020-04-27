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
package threeguys.http.signing.servlet;

import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.config.HttpVerifierBuilder;
import threeguys.http.signing.exceptions.SignatureException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

public class HttpSignatureVerifierFilter implements Filter {

    public static final int UNAUTHORIZED_CODE = 401;
    public static final String UNAUTHORIZED_MESSAGE = "Unauthorized";

    public static final String PARAM_ALGORITHMS = "algorithms";
    public static final String PARAM_KEYSTORE_TYPE = "keystore.type";
    public static final String PARAM_KEYSTORE_PATH = "keystore.path";
    public static final String PARAM_KEYSTORE_PASSWORD = "keystore.password";
    public static final String PARAM_FIELDS = "fields";
    public static final String PARAM_MAX_AGE = "maxAgeSec";

    private HttpVerifier verifier;

    public HttpSignatureVerifierFilter(HttpVerifier verifier) {
        this.verifier = verifier;
    }

    public HttpSignatureVerifierFilter() {
        this(null);
    }

    protected HttpVerifier getVerifier() {
        return verifier;
    }

    @Override
    public void init(FilterConfig config) throws ServletException {
        if (verifier == null) {
            Map<String, String> params = Collections.list(config.getInitParameterNames())
                    .stream().collect(Collectors.toMap(n -> n, config::getInitParameter));

            HttpVerifierBuilder builder = new HttpVerifierBuilder();

            if (params.containsKey(PARAM_ALGORITHMS)) {
                builder.withAlgorithmList(params.get(PARAM_ALGORITHMS));
            }

            if (params.containsKey(PARAM_FIELDS)) {
                builder.withFieldList(params.get(PARAM_FIELDS));
            }

            builder
                .withKeystoreType(params.get(PARAM_KEYSTORE_TYPE))
                .withKeystorePath(params.get(PARAM_KEYSTORE_PATH))
                .withKeystorePassword(params.get(PARAM_KEYSTORE_PASSWORD));

            if (params.containsKey(PARAM_MAX_AGE)) {
                builder.withMaxAge(params.get(PARAM_MAX_AGE));
            }

            try {
                verifier = builder.build();
            } catch (SignatureException e) {
                throw new ServletException(e);
            }
        }
    }

    public boolean doFilter(ServletRequest servletRequest) throws ServletException {
        if (servletRequest instanceof HttpServletRequest) {
            HttpServletRequest request = (HttpServletRequest) servletRequest;

            HttpServletRequestHeaderProvider provider = new HttpServletRequestHeaderProvider(request);
            try {
                verifier.verify(request.getMethod(), request.getRequestURI(), provider);
            } catch (SignatureException e) {
                return false;
            }
        } else {
            throw new ServletException("Invalid request, cannot process " + servletRequest.getClass().getName());
        }

        return true;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        if (!doFilter(servletRequest)) {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.sendError(UNAUTHORIZED_CODE, UNAUTHORIZED_MESSAGE);
            return;
        }

        if (filterChain != null) {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    @Override
    public void destroy() {

    }

}
