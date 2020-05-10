/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.echo;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.WebRequest;
import threeguys.http.signing.examples.server.InMemoryKeyProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;

@Controller
public class EchoController {

    private final Gson gson;
    private final InMemoryKeyProvider keyProvider;

    public EchoController(@Autowired InMemoryKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    private void writeValues(JsonWriter writer, String name, String [] values) throws IOException {
        if (values == null || values.length == 0) {
            writer.name(name).value("");
        } else if (values.length == 1) {
            writer.name(name).value(values[0]);
        } else {
            writer.name(name).beginArray();
            for (String v : values) {
                writer.value(v);
            }
            writer.endArray();
        }
    }

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public @ResponseBody String register(@RequestParam("id") String keyId, @RequestParam("type") String type, @RequestBody String publicKeyPem) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte [] keyData = new PemReader(new StringReader(publicKeyPem)).readPemObject().getContent();
        KeyFactory keyFactory = KeyFactory.getInstance(type);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(keyData));
        keyProvider.put(keyId, publicKey);
        return "OK";
    }

    @RequestMapping(value = "/echo", produces = "application/json")
    public @ResponseBody byte [] echo(WebRequest req) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        JsonWriter writer = gson.newJsonWriter(new OutputStreamWriter(os));

        writer.beginObject()
            .name("user").value(req.getRemoteUser())
            .name("secure").value(req.isSecure())
            .name("sessionId").value(req.getSessionId())
            .name("context").value(req.getContextPath())
            .name("locale")
                .beginObject()
                    .name("country").value(req.getLocale().getCountry())
                    .name("lang").value(req.getLocale().getLanguage())
                    .name("script").value(req.getLocale().getScript())
                .endObject();

        writer.name("headers").beginObject();
        for (Iterator<String> it = req.getHeaderNames(); it.hasNext(); ) {
            String hdr = it.next();
            writeValues(writer, hdr, req.getHeaderValues(hdr));
        }
        writer.endObject();


        writer.name("params").beginObject();
        for (Iterator<String> it = req.getParameterNames(); it.hasNext();) {
            String param = it.next();
            writeValues(writer, param, req.getParameterValues(param));
        }
        writer.endObject();

        writer.endObject();

        writer.flush();
        os.write('\n');
        writer.close();

        return os.toByteArray();
    }

}
