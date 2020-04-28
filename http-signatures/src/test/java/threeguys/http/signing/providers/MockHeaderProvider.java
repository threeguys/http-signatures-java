package threeguys.http.signing.providers;

import java.util.HashMap;
import java.util.Map;

public class MockHeaderProvider implements HeaderProvider {

    private Map<String, String[]> headers;

    public MockHeaderProvider(Map<String, String[]> headers) {
        this.headers = headers;
    }

    public MockHeaderProvider() {
        this(new HashMap<>());
    }

    public MockHeaderProvider add(String name, String ... values) {
        headers.put(name, values);
        return this;
    }

    @Override
    public String[] get(String name) throws Exception {
        return headers.get(name);
    }

}
