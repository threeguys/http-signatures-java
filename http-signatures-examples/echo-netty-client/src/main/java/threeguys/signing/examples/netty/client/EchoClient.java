/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.signing.examples.netty.client;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import threeguys.http.signing.HttpSigner;
import threeguys.http.signing.HttpSignerImpl;
import threeguys.http.signing.Signatures;
import threeguys.http.signing.examples.echo.client.ClientInfo;
import threeguys.http.signing.examples.echo.client.ClientOptions;
import threeguys.http.signing.examples.echo.client.KeyHelper;
import threeguys.http.signing.netty.client.HttpSigningOutboundHandler;
import threeguys.http.signing.providers.SimplePrivateKeyProvider;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.Base64;

public class EchoClient {

    private final SimplePrivateKeyProvider privateKeyProvider;
    private final KeyHelper keyHelper;
    private final HttpSigningOutboundHandler signer;
    private final ClientInfo info;
    private final String keyId;

    public EchoClient(SimplePrivateKeyProvider privateKeyProvider, KeyHelper keyHelper, HttpSigningOutboundHandler signer, ClientInfo info, String keyId) {
        this.privateKeyProvider = privateKeyProvider;
        this.keyHelper = keyHelper;
        this.signer = signer;
        this.info = info;
        this.keyId = keyId;
    }

    private String digest(byte [] body) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return "SHA-256=" + Base64.getEncoder().encodeToString(md.digest(body));
    }

    private HttpRequest generateRegister(ClientOptions opts, byte [] pubKey) throws NoSuchAlgorithmException {
        HttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST,
                            "/register?id=" + keyId + "&type=EC", Unpooled.wrappedBuffer(pubKey));
        request.headers()
                .set(HttpHeaderNames.HOST, opts.getHost())
                .set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE)
                .set(HttpHeaderNames.CONTENT_TYPE, "text/pem")
                .set(HttpHeaderNames.CONTENT_LENGTH, pubKey.length)
                .set(HttpHeaderNames.CONTENT_ENCODING, HttpHeaderValues.IDENTITY)
                .set("Digest", digest(pubKey));

        return request;
    }

    private HttpRequest generateRequest(ClientOptions opts) throws NoSuchAlgorithmException {
        byte [] body = info.getInfo();
        HttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, opts.getPath(),
                                                        Unpooled.wrappedBuffer(body));
        request.headers()
                .set(HttpHeaderNames.HOST, opts.getHost())
                .set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE)
                .set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON)
                .set(HttpHeaderNames.CONTENT_LENGTH, body.length)
                .set(HttpHeaderNames.CONTENT_ENCODING, HttpHeaderValues.IDENTITY)
                .set("Digest", digest(body));

        return request;
    }

    private void execute(Bootstrap bootstrap, ClientOptions opts, HttpRequest request) throws InterruptedException {
        Channel ch = bootstrap.connect(opts.getHost(), opts.getPort()).sync().channel();
        ch.writeAndFlush(request).sync();
        ch.closeFuture().sync();
    }

    private void makeRequest(ClientOptions opts) throws InterruptedException, NoSuchAlgorithmException, IOException {

        byte [] pubKey = keyHelper.loadPublicKeyPem(opts.getKeyPrefix());

        EventLoopGroup workers = new NioEventLoopGroup();
        try {
            Bootstrap bootstrap = new Bootstrap();
            bootstrap
                    .group(workers)
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.SO_KEEPALIVE, true)
                    .handler(new ChannelInitializer<SocketChannel>() {

                        @Override
                        protected void initChannel(SocketChannel ch) throws Exception {
                            ch.pipeline()
                                    .addLast("log", new LoggingHandler(LogLevel.INFO))
                                    .addLast("codec", new HttpClientCodec())
                                    .addLast("signer", signer)
                                    .addLast("handler", new EchoClientHandler());
                        }

                    });

            HttpRequest register = generateRegister(opts, pubKey);
            execute(bootstrap, opts, register);

            HttpRequest request = generateRequest(opts);
            execute(bootstrap, opts, request);

        } finally {
            workers.shutdownGracefully();
        }
    }

    public void run(String... args) throws Exception {
        ClientOptions opts = new ClientOptions(args);
        PrivateKey privKey = keyHelper.loadPrivateKey(opts.getKeyPrefix());

        // This is a hack since we may have generated the key, just set it later
        privateKeyProvider.setKey(privKey);

        makeRequest(opts);
    }

    public static void main(String [] args) throws Exception {
        String keyId = ClientOptions.setKeyId();

        SimplePrivateKeyProvider keyProvider = new SimplePrivateKeyProvider(null);

        HttpSigner signer = new HttpSignerImpl(Clock.systemUTC(),
                                                Signatures.DEFAULT_ALGORITHM,
                                                keyId,
                                                keyProvider,
                                                new Signatures(),
                                                30);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        EchoClient client = new EchoClient(keyProvider,
                                            new KeyHelper(),
                                            new HttpSigningOutboundHandler(signer),
                                            new ClientInfo(gson, keyId),
                                            keyId);
        client.run(args);
    }

}
