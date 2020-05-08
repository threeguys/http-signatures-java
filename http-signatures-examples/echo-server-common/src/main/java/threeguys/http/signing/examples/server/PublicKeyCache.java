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
package threeguys.http.signing.examples.server;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

public class PublicKeyCache extends LinkedHashMap<String, PublicKey> {

    private final int maxEntries;

    public PublicKeyCache(int initialCapacity, int maxEntries) {
        super(initialCapacity, 0.75f, true);
        this.maxEntries = maxEntries;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<String, PublicKey> eldest) {
        return size() > maxEntries;
    }

}
