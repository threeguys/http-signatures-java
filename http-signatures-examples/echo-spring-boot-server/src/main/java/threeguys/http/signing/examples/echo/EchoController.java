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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
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
    public @ResponseBody String register(@RequestParam("id") String keyId, @RequestBody String publicKeyPem) throws NoSuchAlgorithmException, InvalidKeySpecException {
        EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyPem));
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
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
