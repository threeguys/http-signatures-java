/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.spring.client;

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import threeguys.http.signing.examples.client.ClientInfo;
import threeguys.http.signing.examples.client.ClientOptions;
import threeguys.http.signing.examples.client.KeyHelper;
import threeguys.http.signing.providers.SimplePrivateKeyProvider;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.stream.Collectors;

@SpringBootApplication
public class EchoClient implements CommandLineRunner {

    private static final Log log = LogFactory.getLog(EchoClient.class);

    @Autowired
    private SimplePrivateKeyProvider privateKeyProvider;

    @Autowired
    private KeyHelper keyHelper;

    @Autowired
    private Gson gson;

    @Value("${signer.keyId}")
    private String keyId;

    @Autowired
    private RestTemplate client;

    @Autowired
    private ClientInfo info;

    private ClientOptions opts;

    private String digest(byte [] body) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return "SHA-256=" + Base64.getEncoder().encodeToString(md.digest(body));
    }

    private HttpEntity<byte[]> createBody(byte [] data, String contentType) throws NoSuchAlgorithmException {
        HttpHeaders headers = new HttpHeaders();

        headers.set("Content-Type", contentType);
        headers.set("Host", opts.getHost());
        headers.set("Content-Length", String.valueOf(data.length));
        headers.set("Content-Encoding", "identity");
        headers.set("Digest", digest(data));

        return new HttpEntity<>(data, headers);
    }

    private UriComponentsBuilder uriBuilder() {
        return UriComponentsBuilder.newInstance()
                .scheme("http")
                .host(opts.getHost())
                .port(opts.getPort());
    }

    private UriComponentsBuilder uriBuilder(String path) {
        return uriBuilder().path(path);
    }

    private void register() throws IOException, NoSuchAlgorithmException {

        String url = uriBuilder("/register")
                .queryParam("id", keyId)
                .queryParam("type", "EC")
                .toUriString();

        byte [] pubKey = keyHelper.loadPublicKeyPem(opts.getKeyPrefix());
        HttpEntity<byte[]> body = createBody(pubKey, "application/x-pem-file");

        log.info("Registering client: " + url);
        HttpEntity<String> response = client.postForEntity(url,  body, String.class);

        if (!"OK".equals(response.getBody())) {
            throw new IllegalStateException("Could not register with the server!");
        }
    }

    @Override
    public void run(String... args) throws Exception {
        this.opts = new ClientOptions(args);

        PrivateKey privKey = keyHelper.loadPrivateKey(opts.getKeyPrefix());

        // This is a hack since we may have generated the key, just set it later
        privateKeyProvider.setKey(privKey);

        register();

        String url = uriBuilder("/echo").toUriString();
        HttpEntity<String> response = client.postForEntity(url, createBody(info.getInfo(), "application/json"), String.class);
        String headers = response.getHeaders().entrySet().stream()
                .map(e -> e.getKey() + ": " + e.getValue().stream().collect(Collectors.joining(", ")))
                .collect(Collectors.joining("\n"));

        log.info("Echo response received\n==> BEGIN RESPONSE <==\n"
                + headers + "\n" + response.getBody() + "==> END RESPONSE <==\n");
    }

    public static void main(String [] args) throws UnknownHostException {
        ClientOptions.setKeyId();
        SpringApplication.run(new Class<?>[]{ EchoClient.class }, args);
    }

}
