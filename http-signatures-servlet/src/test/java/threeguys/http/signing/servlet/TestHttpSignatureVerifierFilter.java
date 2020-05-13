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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.HttpVerifierImpl;
import threeguys.http.signing.algorithms.SigningAlgorithm;
import threeguys.http.signing.algorithms.SigningAlgorithms;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.mocks.MockHttpVerifier;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static threeguys.http.signing.servlet.HttpSignatureVerifierFilter.PARAM_ALGORITHMS;
import static threeguys.http.signing.servlet.HttpSignatureVerifierFilter.PARAM_FIELDS;
import static threeguys.http.signing.servlet.HttpSignatureVerifierFilter.PARAM_MAX_AGE;

public class TestHttpSignatureVerifierFilter {

    @TempDir
    public Path tempFolder;

    @Test
    public void happyCase() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        HttpSignatureVerifierFilter filter = new HttpSignatureVerifierFilter(new MockHttpVerifier());
        filter.doFilter(request, response, chain);

        assertEquals(request, chain.getRequest());
        assertEquals(response, chain.getResponse());

        filter.destroy();
    }

    @Test
    public void notHttpServletRequest() {
        ServletRequest request = (ServletRequest) Proxy.newProxyInstance(this.getClass().getClassLoader(),
                new Class<?>[]{ServletRequest.class},
                (proxy, method, args) -> null);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        HttpSignatureVerifierFilter filter = new HttpSignatureVerifierFilter(new MockHttpVerifier());
        assertThrows(ServletException.class, () -> filter.doFilter(request, response, chain));
    }

    @Test
    public void badSignature() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        HttpVerifier verifier = new MockHttpVerifier()
                                    .withError(new SignatureException("this is a mock error"));
        HttpSignatureVerifierFilter filter = new HttpSignatureVerifierFilter(verifier);
        filter.doFilter(request, response, chain);

        assertEquals(HttpSignatureVerifierFilter.UNAUTHORIZED_CODE, response.getStatus());
        assertEquals(HttpSignatureVerifierFilter.UNAUTHORIZED_MESSAGE, response.getErrorMessage());

        assertNull(chain.getRequest());
        assertNull(chain.getResponse());

        filter.destroy();
    }

    @Test
    public void goodConfig(@TempDir Path tempDir) throws IOException, ServletException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        char [] password = "your-mom".toCharArray();
        ks.load(null, password);


        File keyStoreFile = tempDir.resolve("keystore").toFile();
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            ks.store(fos, password);
        }

        MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter(PARAM_ALGORITHMS, "rsa-sha256,ecdsa-sha256,my-custom=SomthingThatDoesntExist");
        config.addInitParameter(PARAM_FIELDS, "(request-target),(created),host,content-type");
        config.addInitParameter(PARAM_MAX_AGE, "1234");
        HttpSignatureVerifierFilter filter = new HttpSignatureVerifierFilter();
        filter.init(config);

        HttpVerifierImpl impl = (HttpVerifierImpl) filter.getVerifier();
        assertEquals(1234, impl.getMaxCreateAgeSec());
        assertEquals(Arrays.asList("(request-target)", "(created)", "host", "content-type"), impl.getSigning().getFields());

        Map<String, SigningAlgorithm> expectedAlgos = new HashMap<>();
        expectedAlgos.put("rsa-sha256", SigningAlgorithms.defaultAlgorithms().get("rsa-sha256"));
        expectedAlgos.put("ecdsa-sha256", SigningAlgorithms.defaultAlgorithms().get("ecdsa-sha256"));
        expectedAlgos.put("my-custom", new SigningAlgorithm("my-custom", "SomthingThatDoesntExist"));
        assertEquals(expectedAlgos, impl.getSigning().getAlgorithms());

        filter.destroy();
    }

}
