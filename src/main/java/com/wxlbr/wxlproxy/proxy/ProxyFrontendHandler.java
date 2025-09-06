package com.wxlbr.wxlproxy.proxy;

import com.wxlbr.wxlproxy.cert.CertificateAuthority;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import javax.net.ssl.SSLException;
import io.netty.util.ReferenceCountUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufHolder;
import io.netty.buffer.ByteBufUtil;
import java.nio.charset.StandardCharsets;

import java.net.URI;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

final class ProxyFrontendHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    /**
     * ProxyFrontend to handle HTTP and CONNECT requests.
     */

    // TODO: Use the CertificateAuthority in MITM mode for HTTPS interception
    private final CertificateAuthority ca;

    ProxyFrontendHandler(CertificateAuthority ca) {
        super(false); // disable automatic release
        this.ca = ca;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
        // Handle CONNECT requests for HTTP tunneling

        if (req.method().equals(HttpMethod.CONNECT)) {
            System.out.printf("CONNECT req %s from %s%n", req.uri(), ctx.channel().remoteAddress());
            handleConnect(ctx, req);
        } else {
            logHttpRequest(req, ctx);
            handleHttpForward(ctx, req);
        }
    }

    private void handleConnect(ChannelHandlerContext ctx, FullHttpRequest req) {

        final String hostAndPort = req.uri();
        FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);

        // Switch to a TLS tunnel
        ctx.writeAndFlush(resp).addListener(f -> {
            // Remove HTTP codec and aggregator from pipeline
            ctx.pipeline().remove("httpCodec");
            ctx.pipeline().remove("aggregator");
            ctx.pipeline().remove(this);
            
            // Extract host and port
            final String targetHost;
            final int targetPort;
            if (hostAndPort.contains(":")) {
                String[] parts = hostAndPort.split(":", 2);
                targetHost = parts[0];
                targetPort = Integer.parseInt(parts[1]);
            } else {
                targetHost = hostAndPort;
                targetPort = 443;
            }

            final Channel client = ctx.channel();
            System.out.printf("CONNECT %s — establishing tunnel%n", hostAndPort);

            // TODO: MITM mode with CertificateAuthority
            // For now, just tunnel raw TCP
            // In future, generate dynamic certificate for the target
            // and use a SslContext for the client connection

            // Setup bootstrap for connecting to the target host
            Bootstrap bootstrap = new Bootstrap()
                    .group(client.eventLoop())
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInboundHandlerAdapter());

            // Connect to the target host
            bootstrap.connect(targetHost, targetPort).addListener((ChannelFutureListener) connectFuture -> {
                // If connection to origin fails, close client and log the cause
                if (!connectFuture.isSuccess()) {
                    System.out.printf("CONNECT %s — origin connect failed: %s%n", hostAndPort, connectFuture.cause());

                    // Send 502 Bad Gateway response to client
                    FullHttpResponse failResp = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1,
                        HttpResponseStatus.BAD_GATEWAY
                    );
                    ctx.writeAndFlush(failResp).addListener(ChannelFutureListener.CLOSE);
                    return;
                }

                final Channel origin = connectFuture.channel();
                final AtomicLong upBytes = new AtomicLong();
                final AtomicLong downBytes = new AtomicLong();

                // Relay data from origin -> client (tunnel download)
                origin.pipeline().addLast(new ChannelInboundHandlerAdapter() {

                    @Override public void channelRead(ChannelHandlerContext originCtx, Object msg) {
                        int len = countReadableBytes(msg);
                        downBytes.addAndGet(len);
                        logTunnelData(hostAndPort, "origin->client", msg);
                        writeRetained(client, msg);
                    }

                    @Override public void channelInactive(ChannelHandlerContext originCtx) {
                        System.out.printf("CONNECT %s closed (up=%d B, down=%d B)%n", hostAndPort, upBytes.get(), downBytes.get());
                        if (client.isActive()) {
                            client.close();
                        }
                    }
                });

                // Relay data from client -> origin (tunnel upload)
                client.pipeline().addLast(new ChannelInboundHandlerAdapter() {

                    @Override public void channelRead(ChannelHandlerContext clientCtx, Object msg) {
                        int len = countReadableBytes(msg);
                        upBytes.addAndGet(len);
                        logTunnelData(hostAndPort, "client->origin", msg);
                        writeRetained(origin, msg);
                    }

                    @Override public void channelInactive(ChannelHandlerContext clientCtx) {
                        if (origin.isActive()) {
                            origin.close();
                        }
                    }
                });
            });
        });
    }

    private void handleHttpForward(ChannelHandlerContext ctx, FullHttpRequest req) {

        // Extract host and port
        final long startNs = System.nanoTime();
        final URI uri = URI.create(req.uri());
        final String host = uri.getHost();
        final boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
        final int port = (uri.getPort() == -1) ? (isHttps ? 443 : 80) : uri.getPort();

        // TODO: Replace raw HTTPS forwarding with MITM
        // For now, just forward as-is

        // Prepare origin TLS if required
        final SslContext originSslCtx;
        if (isHttps) {
            try {
                originSslCtx = SslContextBuilder.forClient().build();
            } catch (SSLException e) {
                System.out.printf("Failed to create origin SslContext for %s:%d: %s%n", host, port, e);
                return;
            }
            
        } else {
            originSslCtx = null;
        }

        // Create bootstrap for connecting to origin
        Bootstrap bootstrap = new Bootstrap()
                .group(ctx.channel().eventLoop())
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<Channel>() {

                    @Override
                    protected void initChannel(Channel ch) {

                        // Add SSL handler if required
                        // NOTE: This does not do MITM, just forwards HTTPS as-is when handling 
                        // CONNECT requests. Full MITM would require generating a dynamic certificate
                        if (originSslCtx != null) {
                            ch.pipeline().addFirst(originSslCtx.newHandler(ch.alloc(), host, port));
                        }

                        // Add HTTP client handlers
                        ch.pipeline().addLast(new HttpClientCodec());
                        ch.pipeline().addLast(new HttpObjectAggregator(1024 * 1024));
                        ch.pipeline().addLast(new SimpleChannelInboundHandler<HttpObject>(false) {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ocx, HttpObject msg) {

                                // Log HTTP response
                                if (msg instanceof FullHttpResponse resp) {
                                    int status = resp.status().code();
                                    long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);
                                    System.out.printf("HTTP %s %s <- %d (%d ms, %d B)%n",
                                            req.method(), uri, status,
                                            elapsedMs, resp.content() == null ? -1 : resp.content().readableBytes());
                                    logHttpResponse(resp, ctx);
                                }

                                // forward across channels — retain ownership
                                ctx.writeAndFlush(ReferenceCountUtil.retain(msg));
                            }

                            @Override
                            public void channelInactive(ChannelHandlerContext ocx) {
                                if (ctx.channel().isActive()) {
                                    ctx.channel().flush();
                                }
                            }
                        });
                    }
                });

        // Connect to the origin server
        bootstrap.connect(host, port).addListener((ChannelFutureListener) channelListener -> {

            // Check if the connection was successful
            if (!channelListener.isSuccess()) {
                System.out.printf("HTTP forward: connect to %s:%d failed: %s%n", host, port, channelListener.cause());
                
                // Send 502 Bad Gateway response to client
                FullHttpResponse failResp = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1,
                    HttpResponseStatus.BAD_GATEWAY
                );
                ctx.writeAndFlush(failResp).addListener(ChannelFutureListener.CLOSE);
                return;
            }

            Channel origin = channelListener.channel();

            // Convert absolute-URI -> origin-form when necessary
            FullHttpRequest forward;
            if (uri.getScheme() != null) {

                String path = (uri.getRawPath() == null || uri.getRawPath().isEmpty()) ? "/" : uri.getRawPath();
                if (uri.getRawQuery() != null) {
                    path = path + "?" + uri.getRawQuery();
                }

                // Create a new FullHttpRequest for the origin server
                forward = new DefaultFullHttpRequest(req.protocolVersion(), req.method(), path, req.content().retain());
                forward.headers().setAll(req.headers());
                forward.headers().set(HttpHeaderNames.HOST, host + ((port == 80 || port == 443) ? "" : ":" + port));
            
            } else {
                forward = req.retain();
            }

            // Log the HTTP request being forwarded
            origin.writeAndFlush(forward).addListener(f -> {
                if (!f.isSuccess()) {
                    System.out.printf("HTTP forward: write to origin failed: %s%n", f.cause());

                    // Send 504 Gateway Timeout response to client
                    FullHttpResponse failResp = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1,
                        HttpResponseStatus.GATEWAY_TIMEOUT
                    );
                    ctx.writeAndFlush(failResp).addListener(ChannelFutureListener.CLOSE);
                    origin.close();
                }
            });
        });
    }

    private static int countReadableBytes(Object msg) {
        if (msg instanceof io.netty.buffer.ByteBuf byteBuf) {
            return byteBuf.readableBytes();
        } else if (msg instanceof io.netty.buffer.ByteBufHolder byteBufHolder) {
            return byteBufHolder.content().readableBytes();
        }
        return 0;
    }

    private static void writeRetained(Channel channel, Object msg) {
        // Retain the message and write it to the channel
        channel.writeAndFlush(ReferenceCountUtil.retain(msg));
    }

    private static void logTunnelData(String hostPort, String direction, Object msg) {
        try {

            ByteBuf byteBuf;
            if (msg instanceof ByteBuf tmpByteBuf) {
                byteBuf = tmpByteBuf;
            } else if (msg instanceof ByteBufHolder byteBufHolder) {
                byteBuf = byteBufHolder.content();
            } else {
                return;
            }

            int len = byteBuf.readableBytes();
            int previewLen = Math.min(len, 64);
            String hex = ByteBufUtil.hexDump(byteBuf, byteBuf.readerIndex(), previewLen);
            String txt = byteBuf.toString(byteBuf.readerIndex(), previewLen, StandardCharsets.UTF_8);
            System.out.printf("TUNNEL %s %s %dB preview(hex)=%s preview(txt)=%s%n", hostPort, direction, len, hex, txt);
            
        } catch (Throwable t) {
            System.out.printf("Failed to log tunnel data: %s%n", t.toString());
        }
    }

    private static void logHttpRequest(FullHttpRequest req, ChannelHandlerContext ctx) {
        try {
            StringBuilder builder = new StringBuilder();
            builder.append(req.method()).append(' ').append(req.uri()).append('\n');
            req.headers().forEach(h -> builder.append(h.getKey()).append(": ").append(h.getValue()).append('\n'));
            builder.append('\n');

            if (req.content() != null && req.content().isReadable()) {
                int previewLen = Math.min(req.content().readableBytes(), 256);
                builder.append('\n').append(req.content().toString(req.content().readerIndex(), previewLen, StandardCharsets.UTF_8));
                if (req.content().readableBytes() > previewLen) builder.append("... (truncated)");
            }
            System.out.printf("HTTP REQ from %s\n%s", ctx.channel().remoteAddress(), builder.toString());

        } catch (Throwable t) {
            System.out.printf("Failed to log HTTP request: %s%n", t.toString());
        }
    }

    private static void logHttpResponse(FullHttpResponse resp, ChannelHandlerContext ctx) {
        try {
            StringBuilder builder = new StringBuilder();
            builder.append(resp.status()).append('\n');
            resp.headers().forEach(h -> builder.append(h.getKey()).append(": ").append(h.getValue()).append('\n'));
            builder.append('\n');

            if (resp.content() != null && resp.content().isReadable()) {
                int previewLen = Math.min(resp.content().readableBytes(), 256);
                builder.append('\n').append(resp.content().toString(resp.content().readerIndex(), previewLen, StandardCharsets.UTF_8));
                if (resp.content().readableBytes() > previewLen) builder.append("... (truncated)");
            }
            System.out.printf("HTTP RES to %s\n%s", ctx.channel().remoteAddress(), builder.toString());

        } catch (Throwable t) {
            System.out.printf("Failed to log HTTP response: %s%n", t.toString());
        }
    }
}
