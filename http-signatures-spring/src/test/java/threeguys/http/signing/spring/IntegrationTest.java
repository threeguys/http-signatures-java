package threeguys.http.signing.spring;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import threeguys.http.signing.HttpSigner;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.HttpVerifierImpl;
import threeguys.http.signing.RequestSigning;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.exceptions.KeyNotFoundException;
import threeguys.http.signing.providers.KeyProvider;
import threeguys.http.signing.servlet.HttpSignatureVerifierFilter;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class IntegrationTest {

    @Autowired
    private DemoController controller;

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private SigningClientHttpRequestInterceptor interceptor;

    public static class BaseKeyProvider<T extends Key> {
        private String name;
        private T key;

        public BaseKeyProvider(String name, T key) {
            this.name = name;
            this.key = key;
        }

        protected T getByName(String name) {
            return (this.name.equals(name)) ? this.key : null;
        }
    }

    @SpringBootApplication
    public static class TestApplication {

    }

    @Configuration
    @ComponentScan("threeguys.http.signing.spring")
    public static class TestConfig implements WebMvcConfigurer {

        @Bean
        public HttpSignatureVerifierFilter filter(HttpVerifier verifier) {
            return new HttpSignatureVerifierFilter(verifier);
        }

        @Bean
        public RequestSigning requestSigning() {
            return new RequestSigning();
        }

        @Bean
        public KeyPair keyPair() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256, new SecureRandom());
            return generator.generateKeyPair();
        }

        @Bean
        public KeyProvider<PublicKey> publicKeyProvider(KeyPair keyPair) {
            return new BaseKeyProvider<>("test-key", keyPair.getPublic())::getByName;
        }

        @Bean
        public KeyProvider<PrivateKey> privateKeyProvider(KeyPair keyPair) {
            return new BaseKeyProvider<>("test-key", keyPair.getPrivate())::getByName;
        }

        @Bean
        public HttpVerifier verifier(RequestSigning signing, KeyProvider<PublicKey> keyProvider) {
            return new HttpVerifierImpl(signing, keyProvider);
        }

        @Bean
        public HttpSigner signer(RequestSigning signing, KeyProvider<PrivateKey> keyProvider) throws InvalidSignatureException {
            List<String> fields = Arrays.asList("(request-target)", "(created)");
            return new HttpSigner("ecdsa-sha256", "test-key", keyProvider, fields, signing, 30);
        }

        @Bean
        public HttpSignatureHandlerInterceptor signatureHandlerInterceptor(HttpSignatureVerifierFilter filter) {
            return new HttpSignatureHandlerInterceptor(filter);
        }

        @Bean
        public SigningClientHttpRequestInterceptor clientInterceptor(HttpSigner signer) {
            return new SigningClientHttpRequestInterceptor(signer);
        }

    }

    @Component
    public static class TestWebConfigurer implements WebMvcConfigurer {

        @Autowired
        private HttpSignatureHandlerInterceptor interceptor;

        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(interceptor);
        }
    }

    @Test
    public void something() {
        assertNotNull(controller);
        assertNotNull(restTemplate);

        RestTemplate exec = restTemplate.getRestTemplate();

        exec.getInterceptors().add(interceptor);

        String response = exec.getForObject("http://localhost:" + port + "/?name=dude", String.class);

        assertEquals("Hello, dude!", response);
    }

}
