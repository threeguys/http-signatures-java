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
