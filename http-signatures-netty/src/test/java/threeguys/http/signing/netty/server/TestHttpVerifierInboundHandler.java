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
package threeguys.http.signing.netty.server;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.exceptions.KeyNotFoundException;
import threeguys.http.signing.providers.HeaderProvider;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

public class TestHttpVerifierInboundHandler {

    @Test
    public void channelRead_happyCase() throws Exception {
        HttpVerifier verifier = mock(HttpVerifier.class);
        HttpVerifierInboundHandler handler = new HttpVerifierInboundHandler(verifier);
        ChannelHandlerContext context = mock(ChannelHandlerContext.class);
        DefaultFullHttpRequest msg = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/unit/test");
        msg.headers()
                .add("Content-Type", "application/json")
                .add("Content-MD5", "some-hash-value")
                .add("Host", "foo.com");

        handler.channelRead0(context, msg);
        ArgumentCaptor<String> methodCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> uriCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<HeaderProvider> providerCaptor = ArgumentCaptor.forClass(HeaderProvider.class);

        verify(verifier, times(1)).verify(
                methodCaptor.capture(), uriCaptor.capture(), providerCaptor.capture());

        assertEquals("GET", methodCaptor.getValue());
        assertEquals("/unit/test", uriCaptor.getValue());

        HeaderProvider hp = providerCaptor.getValue();
        for (Map.Entry<String, String> e : msg.headers().entries()) {
            assertArrayEquals(new String[]{ e.getValue() }, hp.get(e.getKey()));
        }
    }

    @Test(expected = KeyNotFoundException.class)
    public void channelRead_verifyFailed() throws Exception {
        HttpVerifier verifier = mock(HttpVerifier.class);
        when(verifier.verify(anyString(), anyString(), any())).thenThrow(new KeyNotFoundException("unit-test"));
        HttpVerifierInboundHandler handler = new HttpVerifierInboundHandler(verifier);
        ChannelHandlerContext context = mock(ChannelHandlerContext.class);
        DefaultFullHttpRequest msg = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/unit/test");
        handler.channelRead0(context, msg);
    }

    @Test
    public void channelReader_notHttpMessage() throws Exception {
        HttpVerifier verifier = mock(HttpVerifier.class);
        HttpVerifierInboundHandler handler = new HttpVerifierInboundHandler(verifier);
        ChannelHandlerContext context = mock(ChannelHandlerContext.class);
        handler.channelRead0(context, new DefaultHttpContent(Unpooled.wrappedBuffer(new byte[]{ 42 })));

        verify(verifier, times(0)).verify(anyString(), anyString(), any());
    }

    @Test
    public void exceptionCaught_happyCase() throws Exception {
        ChannelHandlerContext context = mock(ChannelHandlerContext.class);
        HttpVerifier verifier = mock(HttpVerifier.class);
        HttpVerifierInboundHandler handler = new HttpVerifierInboundHandler(verifier);
        handler.exceptionCaught(context, new KeyNotFoundException("test"));

        ArgumentCaptor<Object> objCaptor = ArgumentCaptor.forClass(Object.class);
        verify(context, times(1)).writeAndFlush(objCaptor.capture());

        DefaultFullHttpResponse response = (DefaultFullHttpResponse) objCaptor.getValue();
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        assertEquals(HttpVersion.HTTP_1_1, response.protocolVersion());
        assertEquals("Unauthorized", new String(response.content().array(), StandardCharsets.UTF_8));
    }

    @Test
    public void exceptionCaught_customMessage() throws Exception {
        ChannelHandlerContext context = mock(ChannelHandlerContext.class);
        HttpVerifier verifier = mock(HttpVerifier.class);
        HttpVerifierInboundHandler handler = new HttpVerifierInboundHandler(verifier, "my-custom-message");
        handler.exceptionCaught(context, new KeyNotFoundException("test"));

        ArgumentCaptor<Object> objCaptor = ArgumentCaptor.forClass(Object.class);
        verify(context, times(1)).writeAndFlush(objCaptor.capture());

        DefaultFullHttpResponse response = (DefaultFullHttpResponse) objCaptor.getValue();
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        assertEquals("my-custom-message", new String(response.content().array(), StandardCharsets.UTF_8));
    }

    @Test
    public void exceptionCaught_notSignatureEx() throws Exception {
        ChannelHandlerContext context = mock(ChannelHandlerContext.class);
        HttpVerifier verifier = mock(HttpVerifier.class);
        HttpVerifierInboundHandler handler = new HttpVerifierInboundHandler(verifier);
        handler.exceptionCaught(context, new IllegalStateException("test"));

        ArgumentCaptor<Object> objCaptor = ArgumentCaptor.forClass(Object.class);
        verify(context, times(0)).writeAndFlush(objCaptor.capture());
    }

    @Test
    public void acceptMessage() throws Exception {
        HttpVerifier verifier = mock(HttpVerifier.class);
        HttpVerifierInboundHandler handler = new HttpVerifierInboundHandler(verifier);

        assertFalse(handler.acceptInboundMessage(13));
        assertFalse(handler.acceptInboundMessage(new DefaultHttpContent(Unpooled.wrappedBuffer("dude".getBytes()))));
        assertFalse(handler.acceptInboundMessage(new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK)));
        assertTrue(handler.acceptInboundMessage(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/yo")));
    }

}
