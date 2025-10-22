package com.wxlbr.wxlproxy.proxy;

import com.wxlbr.wxlproxy.cert.CertificateAuthority;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;

public class ProxyServer {

    /**
     * Proxy server using Netty framework.
     */

    private final String host;
    private final int port;
    private final CertificateAuthority ca;

    private EventLoopGroup boss;
    private EventLoopGroup worker;
    private Channel serverChannel;

    public ProxyServer(String host, int port, CertificateAuthority ca) {
        this.host = host;
        this.port = port;
        this.ca = ca;
    }

    public void start() {
        try {
            // Create boss (acceptor) and worker (client) groups
            boss = new NioEventLoopGroup(1); // One thread to accept incoming connections
            worker = new NioEventLoopGroup();

            // Configure the server
            ServerBootstrap bootstrap = new ServerBootstrap()
                    .group(boss, worker)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new Initializer(ca))
                    .childOption(ChannelOption.AUTO_READ, true);

            // Bind to host + port and start proxy server
            serverChannel = bootstrap.bind(host, port).sync().channel();
            System.out.printf("Proxy listening on %s:%d%n", host, port);
            
            // Block until close
            serverChannel.closeFuture().syncUninterruptibly();
            System.out.println("Proxy stopped");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            stop();
        }
    }

    public void stop() {
        try {
            if (serverChannel != null && serverChannel.isOpen()) {
                serverChannel.close().syncUninterruptibly();
            }
        } catch (Exception ignored) {
            // Ignore for now
        }

        if (boss != null) {
            boss.shutdownGracefully().syncUninterruptibly();
        }
        if (worker != null) {
            worker.shutdownGracefully().syncUninterruptibly();
        }

        System.out.println("Proxy server shut down");
    }

    private static final class Initializer extends ChannelInitializer<SocketChannel> {
        private final CertificateAuthority ca;

        Initializer(CertificateAuthority ca) {
            this.ca = ca;
        }

        @Override
        protected void initChannel(SocketChannel channel) {
            var pipeline = channel.pipeline();

            // Set HTTP codec and aggregator
            pipeline.addLast("httpCodec", new HttpServerCodec());
            pipeline.addLast("aggregator", new HttpObjectAggregator(1024 * 1024));
            pipeline.addLast("frontend", new ProxyFrontendHandler(ca));
        }
    }
}
