/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.echo.client;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestTemplate;
import threeguys.http.signing.providers.SimplePrivateKeyProvider;
import threeguys.http.signing.providers.SimplePublicKeyProvider;
import threeguys.http.signing.spring.SigningClientHttpRequestInterceptor;
import threeguys.http.signing.spring.config.SignaturesConfiguration;
import threeguys.http.signing.spring.config.client.HttpSignerConfiguration;

import java.util.Arrays;
import java.util.List;

import static threeguys.http.signing.Signatures.HEADER_CREATED;
import static threeguys.http.signing.Signatures.HEADER_EXPIRES;
import static threeguys.http.signing.Signatures.HEADER_REQUEST_TARGET;

@Configuration
@Import({
        SignaturesConfiguration.class,
        HttpSignerConfiguration.class,
})
public class SpringConfig {

    @Bean
    public List<String> headers() {
        return Arrays.asList(
                HEADER_REQUEST_TARGET, HEADER_CREATED, HEADER_EXPIRES,
                "Content-Type", "Content-Location", "Content-Encoding", "Content-MD5",
                "Content-Disposition", "Content-Language", "Content-Length", "Content-Range",
                "Content-Security-Policy", "ETag", "Location", "Set-Cookie",
                "Access-Control-Expose-Headers", "User-Agent");
    }

    @Bean
    public SimplePrivateKeyProvider privateKeyProvider() {
        return new SimplePrivateKeyProvider(null);
    }

    @Bean
    public SimplePublicKeyProvider publicKeyProvider() {
        return new SimplePublicKeyProvider(null);
    }

    @Bean
    public ClientInfo info(Gson gson, @Value("${signer.keyId}") String keyId) {
        return new ClientInfo(gson, keyId);
    }

    @Bean
    public Gson gson() {
        return new GsonBuilder().setPrettyPrinting().create();
    }

    @Bean
    public RestTemplate httpClient(SigningClientHttpRequestInterceptor interceptor) {
        return new RestTemplateBuilder()
                .interceptors(interceptor)
                .build();
    }

}
