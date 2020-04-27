package threeguys.http.signing.spring.config.server;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.HttpVerifierImpl;
import threeguys.http.signing.RequestSigning;
import threeguys.http.signing.providers.KeyProvider;
import threeguys.http.signing.servlet.HttpSignatureVerifierFilter;
import threeguys.http.signing.spring.HttpSignatureHandlerInterceptor;

import java.security.PublicKey;
import java.time.Clock;

@Configuration
public class HttpVerifierConfiguration {

    @Value("${verifier.maxAgeSec:60}")
    protected int maxAgeSecs;

    @Bean
    public RequestSigning signing() {
        return new RequestSigning();
    }

    @Bean
    public HttpVerifier verifier(RequestSigning signing, KeyProvider<PublicKey> keyProvider) {
        return new HttpVerifierImpl(Clock.systemUTC(), signing, keyProvider, maxAgeSecs);
    }

    @Bean
    public HttpSignatureHandlerInterceptor interceptor(HttpVerifier verifier) {
        HttpSignatureVerifierFilter filter = new HttpSignatureVerifierFilter(verifier);
        return new HttpSignatureHandlerInterceptor(filter);
    }

}
