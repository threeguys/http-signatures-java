package threeguys.http.signing.examples.echo.client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;
import threeguys.http.signing.providers.SimplePrivateKeyProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

@ShellComponent
public class EchoCommands {

    @Autowired
    private SimplePrivateKeyProvider keyProvider;

    private String address;
    private KeyPair keyPair;

    public EchoCommands() {
        System.err.println("ALPHA!");
    }

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
            keyProvider.setKey(keyPair.getPrivate());
        }

//        new RestTemplateBuilder()
//                .additionalInterceptors();

        return output.append("Successfully registered with " + address).toString();
    }

}
