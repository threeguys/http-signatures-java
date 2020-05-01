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
import threeguys.http.signing.Signatures;
import threeguys.http.signing.exceptions.InvalidSignatureException;
import threeguys.http.signing.servlet.HttpServletRequestHeaderProvider;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

public class SigningClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private HttpSigner signer;

    public SigningClientHttpRequestInterceptor(HttpSigner signer) {
        this.signer = signer;
    }

    private Optional<String []> headers(HttpRequest request, String name) {
        if ("Content-Length".equals(name) && !HttpServletRequestHeaderProvider.isContentMethod(request.getMethod().name())) {
            return Optional.empty();
        }

        List<String> headers = request.getHeaders().get(name);
        if (headers == null) {
            return Optional.empty();
        }

        return Optional.of(headers.toArray(new String[]{}));
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest httpRequest, byte[] bytes, ClientHttpRequestExecution execution) throws IOException {
        try {
            String signature = signer.sign(httpRequest.getMethod().name(), httpRequest.getURI().getPath(),
                    (name) -> headers(httpRequest, name).orElse(null));

            httpRequest.getHeaders().add(Signatures.HEADER, signature);
            return execution.execute(httpRequest, bytes);

        } catch (InvalidSignatureException e) {
            throw new IOException(e);
        }
    }

}
