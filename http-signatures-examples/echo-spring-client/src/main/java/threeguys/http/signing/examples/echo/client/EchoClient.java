package threeguys.http.signing.examples.echo.client;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import threeguys.http.signing.providers.SimplePrivateKeyProvider;
import threeguys.http.signing.spring.config.SignaturesConfiguration;
import threeguys.http.signing.spring.config.client.HttpSignerConfiguration;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static threeguys.http.signing.Signatures.HEADER_CREATED;
import static threeguys.http.signing.Signatures.HEADER_EXPIRES;
import static threeguys.http.signing.Signatures.HEADER_REQUEST_TARGET;

@SpringBootApplication
public class EchoClient {

    @Configuration
    @ComponentScan("threeguys.http.signing.examples.echo.client")
    @Import({ SignaturesConfiguration.class, HttpSignerConfiguration.class })
    public static class AppConfig {

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
        public SimplePrivateKeyProvider keyProvider() {
            return new SimplePrivateKeyProvider((PrivateKey) null);
        }

    }

    public static void main(String [] args) throws UnknownHostException {
        String hostAddress = InetAddress.getLocalHost().getHostAddress();
        String keyId = "echo[" + hostAddress + "/" + new Random().nextInt(10000) + "]";
        System.setProperty("signer.keyId", keyId);
        SpringApplication.run(new Class<?>[]{ EchoClient.class, EchoCommands.class }, args);
    }

}
