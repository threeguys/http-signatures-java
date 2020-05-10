/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.netty;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonWriter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.QueryStringDecoder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class EchoServerHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private void writeValues(JsonWriter writer, String name, String value) throws IOException {
        if (value == null) {
            writer.name(name).value("");
        } else {
            writer.name(name).value(value);
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) throws Exception {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        JsonWriter writer = gson.newJsonWriter(new OutputStreamWriter(os));

        writer.beginObject()
                .name("method").value(req.method().name())
                .name("uri").value(req.uri())
                .name("protocol").value(req.protocolVersion().text());

        writer.name("headers").beginObject();
        for (Map.Entry<String, String> e : req.headers().entries()) {
            writeValues(writer, e.getKey(), e.getValue());
        }
        writer.endObject();


        writer.name("params").beginObject();
        QueryStringDecoder qs = new QueryStringDecoder(req.uri());

        for (Map.Entry<String, List<String>> e : qs.parameters().entrySet()) {
            writeValues(writer, e.getKey(), e.getValue().stream().collect(Collectors.joining(", ")));
        }
        writer.endObject();

        writer.endObject();

        writer.flush();
        os.write('\n');
        writer.close();

        ByteBuf content = Unpooled.copiedBuffer(os.toByteArray());
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
        response.headers()
                .set(HttpHeaderNames.CONTENT_TYPE, "application/json")
                .set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        ctx.write(response);
        ctx.flush();
        ctx.close();
    }

}
