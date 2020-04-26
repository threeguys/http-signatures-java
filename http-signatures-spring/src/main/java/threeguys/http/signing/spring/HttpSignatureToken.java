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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.security.PublicKey;
import java.util.Collection;

public class HttpSignatureToken extends AbstractAuthenticationToken {

    private HttpSignatureUser user;
    private String algorithm;
    private String keyId;
    private PublicKey key;

    public HttpSignatureToken(HttpSignatureUser user, String algorithm, String keyId, PublicKey key, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.user = user;
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.key = key;
    }

    @Override
    public Object getCredentials() {
        return key;
    }

    @Override
    public Object getPrincipal() {
        return user;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getKeyId() {
        return keyId;
    }

}
