/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.netty;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import threeguys.http.signing.HttpVerifier;
import threeguys.http.signing.HttpVerifierImpl;
import threeguys.http.signing.Signatures;
import threeguys.http.signing.examples.server.InMemoryKeyProvider;
import threeguys.http.signing.netty.server.HttpVerifierInboundHandler;

public class EchoServer implements Runnable {

    private final InternalLogger logger;
    private final int port;

    public static class ServerInitializer extends ChannelInitializer<Channel> {

        private static final int MAX_HTTP_OBJECT_SIZE = 128 * 1024 * 1024;

        private final HttpVerifier verifier;
        private final InMemoryKeyProvider keyProvider;

        public ServerInitializer(HttpVerifier verifier, InMemoryKeyProvider keyProvider) {
            this.verifier = verifier;
            this.keyProvider = keyProvider;
        }

        @Override
        protected void initChannel(Channel ch) {
            ChannelPipeline pipeline = ch.pipeline();
            pipeline.addLast(new HttpServerCodec())
                    .addLast(new HttpObjectAggregator(MAX_HTTP_OBJECT_SIZE))
                    .addLast(new LoggingHandler(LogLevel.INFO))
                    .addLast(new RegisterHandler(keyProvider))
                    .addLast(new HttpVerifierInboundHandler(verifier))
                    .addLast(new EchoServerHandler());
        }

    }

    public EchoServer(int port) {
        this.logger = InternalLoggerFactory.getInstance(EchoServer.class);
        this.port = port;
    }

    @Override
    public void run() {
        EventLoopGroup managerGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup();

        Signatures signatures = new Signatures();
        InMemoryKeyProvider provider = new InMemoryKeyProvider();
        HttpVerifier verifier = new HttpVerifierImpl(signatures, provider);

        try {
            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap
                    .group(managerGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ServerInitializer(verifier, provider))
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true);

            ChannelFuture channel = bootstrap.bind(port).sync();
            channel.channel().closeFuture().sync();
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        } finally {
            workerGroup.shutdownGracefully();
            managerGroup.shutdownGracefully();
        }

    }

    public static void main(String [] args) throws Exception {
        int port = (args.length > 0) ? Integer.parseInt(args[0]) : 8080;
        System.out.println("Starting netty echo server, http://localhost:" + port);
        new EchoServer(port).run();
    }

}
