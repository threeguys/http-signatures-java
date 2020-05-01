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
package threeguys.http.signing.servlet;

import threeguys.http.signing.Signatures;
import threeguys.http.signing.providers.HeaderProvider;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class HttpServletRequestHeaderProvider implements HeaderProvider {

    private final HttpServletRequest request;
    private final Map<String, String> nameMappings;

    public static final String NAME_CONTENT_LENGTH = "content-length";

    public HttpServletRequestHeaderProvider(HttpServletRequest request) {
        this.request = request;
        this.nameMappings = Collections.unmodifiableMap(Collections.list(this.request.getHeaderNames()).stream()
                .collect(Collectors.toMap(Signatures::canonicalizeName, (n) -> n)));
    }

    public static boolean isContentMethod(String method) {
        return "post".equals(method.toLowerCase());
    }

    @Override
    public String[] get(String name) {
        String canonicalName = Signatures.canonicalizeName(name);
        String mappedName = nameMappings.get(canonicalName);

        if (mappedName == null) {
            switch (canonicalName) {
                case NAME_CONTENT_LENGTH:
                    return isContentMethod(request.getMethod())
                            ? new String[] { Integer.toString(request.getContentLength()) }
                            : null;
                default:
                    break;
            }
            return null;
        }

        List<String> headers = Collections.list(request.getHeaders(name));
        return (headers.size() == 0) ? null : headers.toArray(new String[] {});
    }

}
