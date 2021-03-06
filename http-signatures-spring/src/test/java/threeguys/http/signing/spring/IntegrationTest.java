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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.CommonsRequestLoggingFilter;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import threeguys.http.signing.Signatures;
import threeguys.http.signing.providers.KeyProvider;
import threeguys.http.signing.providers.SimplePrivateKeyProvider;
import threeguys.http.signing.providers.SimplePublicKeyProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static threeguys.http.signing.Signatures.DEFAULT_ALGORITHM;
import static threeguys.http.signing.Signatures.HEADER_CREATED;
import static threeguys.http.signing.Signatures.HEADER_EXPIRES;
import static threeguys.http.signing.Signatures.HEADER_REQUEST_TARGET;
import static threeguys.http.signing.Signatures.defaultFields;
import static threeguys.http.signing.algorithms.SigningAlgorithms.defaultAlgorithms;

@ExtendWith(SpringExtension.class)
//@SpringBootTest(
//        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
//        properties = { "signer.keyId=" + IntegrationTest.INTEG_TEST_KEY_ID }
//)
//@Configuration
//@ComponentScan(excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = SignaturesConfiguration.class))
//@SpringBootApplication(excludeName = "threeguys.http.signing.spring.config.*")
//@ActiveProfiles("unit-test")
@ContextConfiguration
public class IntegrationTest {

    public static final String INTEG_TEST_KEY_ID = "integration-test-key-id";

    @Autowired
    private DemoController controller;

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private SigningClientHttpRequestInterceptor interceptor;

    @Controller
    public static class DemoController {

        @RequestMapping("/")
        public @ResponseBody
        String helloWorld(@RequestParam("name") String name) {
            return "Hello, " + name + "!";
        }

    }

    @Configuration
    public static class KeyProviderConfig {

        @Bean
        public KeyPair keyPair() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256, new SecureRandom());
            return generator.generateKeyPair();
        }

        @Bean
        public KeyProvider<PublicKey> publicKeyProvider(KeyPair keyPair) {
            return new SimplePublicKeyProvider(keyPair.getPublic());
        }

        @Bean
        public KeyProvider<PrivateKey> privateKeyProvider(KeyPair keyPair) {
            return new SimplePrivateKeyProvider(keyPair.getPrivate());
        }

    }

    @Configuration
    public static class TestSignaturesConfiguration {

        @Bean
        public Signatures signatures() {
            return new Signatures(DEFAULT_ALGORITHM, defaultAlgorithms(), defaultFields(),
                    Arrays.asList(HEADER_REQUEST_TARGET, HEADER_CREATED, HEADER_EXPIRES,
                                    "X-Foo-Id", "Content-Length", "Content-MD5"));
        }

    }

    @Component
    public static class TestWebConfigurer implements WebMvcConfigurer {

        @Autowired
        private HttpSignatureHandlerInterceptor interceptor;

        @Bean
        public CommonsRequestLoggingFilter loggingFilter() {
            CommonsRequestLoggingFilter filter = new CommonsRequestLoggingFilter();
            filter.setIncludeQueryString(true);
            filter.setIncludeClientInfo(true);
            filter.setIncludeHeaders(true);
            filter.setIncludePayload(true);
            return filter;
        }

        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(interceptor);
        }

    }

    @Test
    public void something() {
        Security.addProvider(new BouncyCastleProvider());
        assertNotNull(controller);
        assertNotNull(restTemplate);

        String myFooId = "foo-" + Integer.toHexString(new Random().nextInt());

        RestTemplate exec = restTemplate.getRestTemplate();
        exec.getInterceptors().add(interceptor);
        exec.getClientHttpRequestInitializers().add(request -> request.getHeaders().add("X-Foo-Id", myFooId));

        String response = exec.getForObject("http://localhost:" + port + "/?name=dude", String.class);
        assertEquals("Hello, dude!", response);
    }

}
