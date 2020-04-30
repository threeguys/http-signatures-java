package threeguys.http.signing.examples.echo.client;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;
import threeguys.http.signing.HttpSigner;
import threeguys.http.signing.providers.SimplePrivateKeyProvider;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static threeguys.http.signing.Signatures.*;

@SpringBootApplication
@ComponentScan({
        "threeguys.http.signing.examples.echo.client"
})
@ShellComponent
public class EchoClient {

    @Autowired
    private HttpSigner signer;

    @Autowired
    private SimplePrivateKeyProvider keyProvider;

    @Configuration
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

    }

    private String address;
    private KeyPair keyPair;

    @ShellMethod("Sets the address of the server")
    public String server(@ShellOption(value = {"-A", "--address"}, defaultValue = "localhost:8080") String address) {
        this.address = address;
        return "Set server address to: " + address;
    }

    @ShellMethod("Generate key and register with server")
    public String register() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        StringBuilder output = new StringBuilder();
        if (keyPair == null) {
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(ecSpec, new SecureRandom());
            keyPair = generator.generateKeyPair();
            output.append("Generated new ecdsa key-pair\n");
        }

//        new RestTemplateBuilder()
//                .additionalInterceptors();

        return output.append("Successfully registered with " + address).toString();
    }

    public static void main(String [] args) throws UnknownHostException {
        String hostAddress = InetAddress.getLocalHost().getHostAddress();
        String keyId = "echo[" + hostAddress + "/" + new Random().nextInt(10000) + "]";
        SpringApplication.run(EchoClient.class, args);
    }

}
