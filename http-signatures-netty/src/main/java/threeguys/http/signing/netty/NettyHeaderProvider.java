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
package threeguys.http.signing.netty;

import io.netty.handler.codec.http.HttpHeaders;
import threeguys.http.signing.providers.HeaderProvider;

public class NettyHeaderProvider implements HeaderProvider {

    private HttpHeaders headers;

    public NettyHeaderProvider(HttpHeaders headers) {
        this.headers = headers;
    }

    @Override
    public String[] get(String name) throws Exception {
        return headers.getAll(name).toArray(new String[]{});
    }

}
