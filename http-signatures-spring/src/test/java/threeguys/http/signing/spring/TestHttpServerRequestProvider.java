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
package threeguys.http.signing.spring;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import threeguys.http.signing.providers.HeaderProvider;

import static threeguys.http.signing.RequestSigning.*;

import static org.junit.Assert.*;

public class TestHttpServerRequestProvider {

    @Test
    public void happyCase() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HEADER, "example-signature");
        request.addHeader("Multi-Value-Header", "one,two,three");
        request.addHeader("Empty-Header", "");

        HeaderProvider provider = new HttpServletRequestProvider(request);
        assertArrayEquals(new String[] { "one,two,three" }, provider.get("Multi-Value-Header"));
        assertArrayEquals(new String[] { "" }, provider.get("Empty-Header"));
        assertArrayEquals(new String[] { "example-signature" }, provider.get(HEADER));
    }

}
