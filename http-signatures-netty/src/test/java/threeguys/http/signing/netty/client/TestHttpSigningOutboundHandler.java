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
package threeguys.http.signing.netty.client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import threeguys.http.signing.HttpSigner;
import threeguys.http.signing.Signatures;
import threeguys.http.signing.providers.HeaderProvider;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

public class TestHttpSigningOutboundHandler {

    @Test
    public void happyCase() throws Exception {
        HttpSigner signer = mock(HttpSigner.class);
        when(signer.sign(any(), any(), any())).thenReturn("this-is-the-signature");
        HttpSigningOutboundHandler handler = new HttpSigningOutboundHandler(signer);

        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
        ChannelPromise promise = mock(ChannelPromise.class);
        Object msg = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/testing");
        handler.write(ctx, msg, promise);

        ArgumentCaptor<String> methodCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> uriCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<HeaderProvider> hpCaptor = ArgumentCaptor.forClass(HeaderProvider.class);
        verify(signer, times(1)).sign(methodCaptor.capture(), uriCaptor.capture(), hpCaptor.capture());

        assertEquals("GET", methodCaptor.getValue());
        assertEquals("/testing", uriCaptor.getValue());
        assertArrayEquals(new String[] { "this-is-the-signature" }, hpCaptor.getValue().get(Signatures.HEADER));
    }

}
