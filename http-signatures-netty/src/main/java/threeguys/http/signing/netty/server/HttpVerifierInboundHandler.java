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
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.exceptions.SignatureException;
import threeguys.http.signing.netty.NettyHeaderProvider;

import java.nio.charset.StandardCharsets;

public class HttpVerifierInboundHandler extends ChannelInboundHandlerAdapter {

    public static final String DEFAULT_UNAUTHORIZED_MESSAGE = "Unauthorized";

    private final HttpVerifier verifier;
    private final byte [] message;

    public HttpVerifierInboundHandler(HttpVerifier verifier) {
        this(verifier, DEFAULT_UNAUTHORIZED_MESSAGE);
    }

    public HttpVerifierInboundHandler(HttpVerifier verifier, String message) {
        this.verifier = verifier;
        this.message = message.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HttpRequest) {
            HttpRequest req = (HttpRequest) msg;
            verifier.verify(req.method().toString(), req.uri(), new NettyHeaderProvider(req.headers()));
        }
        super.channelRead(ctx, msg);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (cause instanceof SignatureException) {
            ctx.writeAndFlush(new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1,
                    HttpResponseStatus.UNAUTHORIZED,
                    Unpooled.wrappedBuffer(message)));
        } else{
            super.exceptionCaught(ctx, cause);
        }
    }
}
