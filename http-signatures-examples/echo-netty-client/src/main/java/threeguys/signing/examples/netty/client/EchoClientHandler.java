/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.signing.examples.netty.client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.CharsetUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.util.stream.Collectors;

public class EchoClientHandler extends SimpleChannelInboundHandler<HttpObject> {

    private static final InternalLogger log = InternalLoggerFactory.getInstance(EchoClientHandler.class);

    private StringBuilder data = new StringBuilder();

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) throws Exception {
        if (msg instanceof HttpResponse) {
            HttpResponse response = (HttpResponse) msg;
            log.info("Response status: " + response.status().code() + " " + response.status().reasonPhrase()
                        + " " + response.protocolVersion().text());

            String headers = response.headers().entries().stream()
                    .map(e -> String.format("%s: \"%s\"", e.getKey(), e.getValue()))
                    .collect(Collectors.joining("\n"));

            if (headers.length() > 0) {
                log.info("==> Begin Headers <==\n" + headers + "\n==> End Headers <==");
            } else {
                log.info("No headers in the response");
            }
        }

        if (msg instanceof HttpContent) {
            String body = ((HttpContent) msg).content().toString(CharsetUtil.UTF_8);
            if (body.length() > 0) {
                data.append(body);
            }

            if (msg instanceof LastHttpContent) {
                log.info("==> BEGIN RESPONSE <==\n" + data.toString() + "==> END RESPONSE <==\n");
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        log.error("Exception in channel: " + ctx.name(), cause);
    }

}
