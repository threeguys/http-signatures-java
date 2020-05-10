/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.echo;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.WebRequest;
import threeguys.http.signing.examples.server.InMemoryKeyProvider;
import threeguys.http.signing.examples.server.ServerHelper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;

@Controller
public class EchoController {

    private final Gson gson;
    private final InMemoryKeyProvider keyProvider;
    private final ServerHelper serverHelper;

    public EchoController(@Autowired InMemoryKeyProvider keyProvider, @Autowired ServerHelper serverHelper) {
        this.keyProvider = keyProvider;
        this.serverHelper = serverHelper;
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
        keyProvider.put(keyId, serverHelper.readKey(type, publicKeyPem));
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
