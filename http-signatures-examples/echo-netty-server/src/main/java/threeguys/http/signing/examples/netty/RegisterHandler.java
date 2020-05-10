package threeguys.http.signing.examples.netty;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.QueryStringDecoder;
import threeguys.http.signing.examples.server.InMemoryKeyProvider;

import java.nio.charset.StandardCharsets;

public class RegisterHandler extends ChannelInboundHandlerAdapter {

    private final InMemoryKeyProvider keyProvider;

    public RegisterHandler(InMemoryKeyProvider keyProvider) {
        super();
        this.keyProvider = keyProvider;
    }

    private String getParameter(QueryStringDecoder qs, String name) {
        return String.join(", ", qs.parameters().get(name));
    }

    private void handle(ChannelHandlerContext ctx, HttpRequest request) throws Exception {
        QueryStringDecoder qs = new QueryStringDecoder(request.uri());

        if ("/register".equals(qs.path())) {
            String type = getParameter(qs, "type");
            String keyId = getParameter(qs, "id");

            if (request instanceof HttpContent) {
                HttpContent content = (HttpContent) request;
                ByteBuf buffer = content.content();
                byte [] data = new byte[buffer.readableBytes()];
                buffer.getBytes(0, data);

                keyProvider.put(keyId, type, new String(data, StandardCharsets.UTF_8));

                ctx.write(new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
                ctx.flush();
                ctx.close();
            }

        } else {
            super.channelRead(ctx, request);
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HttpRequest) {
            handle(ctx, (HttpRequest) msg);
        } else {
            super.channelRead(ctx, msg);
        }
    }

}
