/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.spring;

import com.google.gson.Gson;
import com.google.gson.stream.JsonWriter;
import org.springframework.web.context.request.WebRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Iterator;

public class EchoGenerator {

    private final Gson gson;

    public EchoGenerator(Gson gson) {
        this.gson = gson;
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

    public byte [] echo(WebRequest req) throws IOException {
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
