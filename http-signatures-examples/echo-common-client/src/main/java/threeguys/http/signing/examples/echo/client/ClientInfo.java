package threeguys.http.signing.examples.echo.client;

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class ClientInfo {

    private final Gson gson;
    private String keyId;

    public ClientInfo(Gson gson, String keyId) {
        this.gson = gson;
        this.keyId = keyId;
    }

    public byte [] getInfo() {
        Runtime rt = Runtime.getRuntime();
        Map<String, Object> specs = new HashMap<>();
        specs.put("free", rt.freeMemory());
        specs.put("max", rt.maxMemory());
        specs.put("total", rt.totalMemory());
        specs.put("proc", rt.availableProcessors());

        Map<String, Object> content = new HashMap<>();
        content.put("ts", new Date().getTime());
        content.put("key", keyId);
        content.put("specs", specs);

        return gson.toJson(content).getBytes(StandardCharsets.UTF_8);
    }

}
