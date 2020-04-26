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

import java.security.PublicKey;

public class MockPublicKey implements PublicKey  {

    private final String algorithm;
    private final String format;
    private final byte[] encoded;

    public MockPublicKey(String algorithm, String format, byte[] encoded) {
        this.algorithm = algorithm;
        this.format = format;
        this.encoded = encoded;
    }

    public MockPublicKey() {
        this("mock-algo", "mock-format", new byte[] { 'm', 'o', 'c', 'k', '-', 'd', 'a', 't', 'a' });
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return format;
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

}
