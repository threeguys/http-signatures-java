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
package threeguys.http.signing.providers;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static threeguys.http.signing.Signatures.canonicalizeName;

public class MockHeaderProvider implements HeaderProvider {

    private Map<String, String[]> headers;

    public MockHeaderProvider(Set<Map.Entry<String, String>> headers) {
        this(headers.stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> new String[] { e.getValue() })));
    }

    public MockHeaderProvider(Map<String, String[]> headers) {
        this.headers = headers.entrySet().stream()
            .collect(Collectors.toMap(e -> canonicalizeName(e.getKey()), Map.Entry<String, String[]>::getValue));
    }

    public MockHeaderProvider() {
        this(new HashMap<>());
    }

    public MockHeaderProvider add(String name, String ... values) {
        headers.put(canonicalizeName(name), values);
        return this;
    }

    @Override
    public String[] get(String name) throws Exception {
        return headers.get(canonicalizeName(name));
    }

}
