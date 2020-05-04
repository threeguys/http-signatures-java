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
package threeguys.http.signing.spring.config.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import threeguys.http.signing.HttpSigner;
import threeguys.http.signing.HttpSignerImpl;
import threeguys.http.signing.Signatures;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.providers.KeyProvider;
import threeguys.http.signing.spring.SigningClientHttpRequestInterceptor;
import threeguys.http.signing.spring.config.SignaturesConfiguration;

import java.security.PrivateKey;
import java.util.List;

@Configuration
public class HttpSignerConfiguration {

    @Value("${signer.expirationSec:60}")
    private int expirationSec;

    @Value("${signer.keyId}")
    private String keyId;

    @Bean
    public HttpSigner signer(KeyProvider<PrivateKey> keyProvider, Signatures signatures) throws InvalidSignatureException {
        return new HttpSignerImpl("ecdsa-sha256", keyId, keyProvider, signatures, expirationSec);
    }

    @Bean
    public SigningClientHttpRequestInterceptor clientInterceptor(HttpSigner signer) {
        return new SigningClientHttpRequestInterceptor(signer);
    }

}
