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
package threeguys.http.signing.spring.config.server;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.HttpVerifierImpl;
import threeguys.http.signing.Signatures;
import threeguys.http.signing.providers.KeyProvider;
import threeguys.http.signing.spring.HttpSignatureHandlerInterceptor;

import java.security.PublicKey;
import java.time.Clock;

@Configuration
public class HttpVerifierConfiguration {

    @Value("${verifier.maxAgeSec:60}")
    protected int maxAgeSecs;

    @Bean
    public HttpVerifier verifier(Signatures signatures, KeyProvider<PublicKey> keyProvider) {
        return new HttpVerifierImpl(Clock.systemUTC(), signatures, keyProvider, maxAgeSecs);
    }

    @Bean
    public HttpSignatureHandlerInterceptor interceptor(HttpVerifier verifier) {
        return new HttpSignatureHandlerInterceptor(verifier);
    }

}
