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

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import threeguys.http.signing.HttpSigner;
import threeguys.http.signing.RequestSigning;
import threeguys.http.signing.exceptions.InvalidSignatureException;

import java.io.IOException;

public class SigningClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private HttpSigner signer;

    public SigningClientHttpRequestInterceptor(HttpSigner signer) {
        this.signer = signer;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest httpRequest, byte[] bytes, ClientHttpRequestExecution execution) throws IOException {
        try {
            String signature = signer.sign(httpRequest.getMethod().name(), httpRequest.getURI().getPath(),
                    (name) -> httpRequest.getHeaders().get(name).toArray(new String[]{}));

            httpRequest.getHeaders().add(RequestSigning.HEADER, signature);
            return execution.execute(httpRequest, bytes);

        } catch (InvalidSignatureException e) {
            throw new IOException(e);
        }
    }

}
