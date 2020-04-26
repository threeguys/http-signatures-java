package threeguys.http.signing.servlet;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.HttpVerifierImpl;
import threeguys.http.signing.RequestSigning;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.mocks.MockHttpVerifier;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static threeguys.http.signing.servlet.HttpSignatureVerifierFilter.*;

public class TestHttpSignatureVerifierFilter {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void happyCase() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        HttpSignatureVerifierFilter filter = new HttpSignatureVerifierFilter(new MockHttpVerifier());
        filter.doFilter(request, response, chain);

        assertEquals(request, chain.getRequest());
        assertEquals(response, chain.getResponse());
    }

    @Test(expected = ServletException.class)
    public void notHttpServletRequest() throws IOException, ServletException {
        ServletRequest request = (ServletRequest) Proxy.newProxyInstance(this.getClass().getClassLoader(),
                new Class<?>[]{ServletRequest.class},
                (proxy, method, args) -> null);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        HttpSignatureVerifierFilter filter = new HttpSignatureVerifierFilter(new MockHttpVerifier());
        filter.doFilter(request, response, chain);
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
    }

    @Test
    public void goodConfig() throws IOException, ServletException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        char [] password = "your-mom".toCharArray();
        ks.load(null, password);

        File keyStoreFile = tempFolder.newFile();
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            ks.store(fos, password);
        }

        MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter(PARAM_ALGORITHMS, "rsa-sha256,ecdsa-sha256,my-custom=SomthingThatDoesntExist");
        config.addInitParameter(PARAM_FIELDS, "(request-target),(created),host,content-type");
        config.addInitParameter(PARAM_MAX_AGE, "1234");
        config.addInitParameter(PARAM_KEYSTORE_TYPE, KeyStore.getDefaultType());
        config.addInitParameter(PARAM_KEYSTORE_PATH, keyStoreFile.getAbsolutePath());
        config.addInitParameter(PARAM_KEYSTORE_PASSWORD, "your-mom");
        HttpSignatureVerifierFilter filter = new HttpSignatureVerifierFilter();
        filter.init(config);

        HttpVerifierImpl impl = (HttpVerifierImpl) filter.getVerifier();
        assertEquals(1234, impl.getMaxCreateAgeSec());
        assertEquals(Arrays.asList("(request-target)", "(created)", "host", "content-type"), impl.getSigning().getFields());

        Map<String, String> expectedAlgos = new HashMap<>();
        expectedAlgos.put("rsa-sha256", RequestSigning.defaultAlgorithms().get("rsa-sha256"));
        expectedAlgos.put("ecdsa-sha256", RequestSigning.defaultAlgorithms().get("ecdsa-sha256"));
        expectedAlgos.put("my-custom", "SomthingThatDoesntExist");
        assertEquals(expectedAlgos, impl.getSigning().getAlgorithms());
    }

}
