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
package threeguys.http.signing.mocks;

import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.VerificationResult;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.providers.HeaderProvider;

public class MockHttpVerifier implements HttpVerifier {

    private VerificationResult result;
    private SignatureException error;

    public MockHttpVerifier() {
    }

    public MockHttpVerifier(VerificationResult result, SignatureException error) {
        this.result = result;
        this.error = error;
    }

    public void setResult(VerificationResult result) {
        this.result = result;
    }

    public void setError(SignatureException error) {
        this.error = error;
    }

    public MockHttpVerifier withResult(VerificationResult result) {
        setResult(result);
        return this;
    }

    public MockHttpVerifier withError(SignatureException error) {
        setError(error);
        return this;
    }

    @Override
    public VerificationResult verify(String method, String url, HeaderProvider provider) throws SignatureException {
        if (error != null) {
            throw error;
        }
        return result;
    }
}
