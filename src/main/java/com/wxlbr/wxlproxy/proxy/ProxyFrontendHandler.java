package com.wxlbr.wxlproxy.proxy;

import com.wxlbr.wxlproxy.cert.CertificateAuthority;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.util.ReferenceCountUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

final class ProxyFrontendHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    /**
     * ProxyFrontend to handle HTTP and CONNECT requests.
     * and HTTPS MITM interception.
     */

    private final CertificateAuthority ca;
    private final BufferedReader consoleReader;

    ProxyFrontendHandler(CertificateAuthority ca) {
        super(false); // disable automatic release
        this.ca = ca;
        this.consoleReader = new BufferedReader(new InputStreamReader(System.in));
    }

    private void waitForUserInput(String prompt) {
        // Wait for user to press Enter before forwarding the request/response
        // Current placeholder for editing functionality
        try {
            System.out.println("\n" + prompt);
            System.out.print("Press ENTER to continue...");
            consoleReader.readLine();
            System.out.println("Continuing...\n");
        } catch (Exception e) {
            System.err.println("Error reading user input: " + e.getMessage());
        }
    }


    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
        // Handle CONNECT requests for HTTP tunneling

        if (req.method().equals(HttpMethod.CONNECT)) {
            // CONNECT request
            System.out.printf("CONNECT req %s from %s%n", req.uri(), ctx.channel().remoteAddress());
            handleConnect(ctx, req);
        } else {
            // Regular HTTP request
            logHttpRequest(req, ctx);
            handleHttpForward(ctx, req);
        }
    }

    private void handleConnect(ChannelHandlerContext ctx, FullHttpRequest req) {
        final String hostAndPort = req.uri();
        FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);

        ctx.writeAndFlush(resp).addListener(f -> {
            ctx.pipeline().remove("httpCodec");
            ctx.pipeline().remove("aggregator");
            ctx.pipeline().remove(this);

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
            System.out.printf("CONNECT %s — establishing MITM tunnel%n", hostAndPort);

            try {
                // Generate dynamic cert for targetHost
                X509Certificate cert = ca.getOrCreateCertForHost(targetHost);
                PrivateKey key = ca.getPrivateKeyForHost(targetHost);

                // Create SslContext for client side
                try {
                    SslContext sslCtx = SslContextBuilder
                        .forServer(key, cert)
                        .build();

                    // Add SslHandler to pipeline
                    client.pipeline().addFirst("ssl", sslCtx.newHandler(client.alloc()));

                    // Add HTTP handlers and a forwarding handler
                    client.pipeline().addLast("httpCodec", new HttpServerCodec());
                    client.pipeline().addLast("aggregator", new HttpObjectAggregator(1024 * 1024));
                    client.pipeline().addLast("mitmForwarder", new SimpleChannelInboundHandler<FullHttpRequest>(false) {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx2, FullHttpRequest req2) {
                            logHttpRequest(req2, ctx2);
                            handleHttpsForward(ctx2, req2, targetHost, targetPort);
                        }
                    });
                } catch (Exception e) {
                    e.printStackTrace();
                    throw e;
                }

            } catch (Exception e) {
                System.out.printf("MITM setup failed for %s: %s%n", hostAndPort, e);
                client.close();
            }
        });
    }

    private void handleHttpsForward(ChannelHandlerContext ctx, FullHttpRequest req, String targetHost, int targetPort) {
        // Forward HTTPS requests after ssl handshake (MITM)
        
        final long startNs = System.nanoTime();
        final String path = req.uri();

        // Intercept request
        // TODO: allow user to edit request before forwarding
        logHttpRequest(req, ctx);
        waitForUserInput("\nINTERCEPTED HTTPS REQUEST to " + targetHost + ":" + targetPort + path);

        // Connect to the origin server with TLS 
        // Using Netty's InsecureTrustManagerFactory for testing 
        // to avoid certificate validation issues
        SslContext originSslCtx;
        try {
            originSslCtx = SslContextBuilder.forClient()
                .trustManager(io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                .build();
        } catch (Exception e) {
            System.out.printf("Failed to create origin SslContext for %s:%d: %s%n", targetHost, targetPort, e);
            sendErrorResponse(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR);
            return;
        }

        connectAndForward(ctx, req, targetHost, targetPort, path, originSslCtx, startNs, true);
    }

    private void handleHttpForward(ChannelHandlerContext ctx, FullHttpRequest req) {
        // Forward plain HTTP requests (non-CONNECT)

        final long startNs = System.nanoTime();
        final URI uri = URI.create(req.uri());
        final String host = uri.getHost();
        final int port = (uri.getPort() == -1) ? 80 : uri.getPort();

        String path = (uri.getRawPath() == null || uri.getRawPath().isEmpty()) ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null) {
            path = path + "?" + uri.getRawQuery();
        }

        // Intercept request
        // TODO: allow user to edit request before forwarding
        logHttpRequest(req, ctx);
        waitForUserInput("\nINTERCEPTED HTTP REQUEST to " + req.uri());

        connectAndForward(ctx, req, host, port, path, null, startNs, false);
    }

    private void connectAndForward(ChannelHandlerContext ctx, FullHttpRequest req, 
                                   String targetHost, int targetPort, String path,
                                   SslContext sslContext, long startNs, boolean isMitm) {
        
        // Connect to server and forward the request for both HTTP and HTTPS
        String protocol = isMitm ? "HTTPS" : (sslContext != null ? "HTTPS" : "HTTP");

        Bootstrap bootstrap = new Bootstrap()
                .group(ctx.channel().eventLoop())
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        // Add SSL handler if needed
                        if (sslContext != null) {
                            ch.pipeline().addFirst(sslContext.newHandler(ch.alloc(), targetHost, targetPort));
                        }
                        ch.pipeline().addLast(new HttpClientCodec());
                        ch.pipeline().addLast(new HttpObjectAggregator(1024 * 1024));
                        ch.pipeline().addLast(new SimpleChannelInboundHandler<HttpObject>(false) {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ocx, HttpObject msg) {
                                if (msg instanceof FullHttpResponse resp) {
                                    int status = resp.status().code();
                                    long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);
                                    int bytes = resp.content() == null ? -1 : resp.content().readableBytes();
                                    
                                    System.out.printf("%s MITM %s %s:%d%s <- %d (%d ms, %d B)%n",
                                            protocol, req.method(), targetHost, targetPort, path, status, elapsedMs, bytes);
                                    logHttpResponse(resp, ctx);
                                    
                                    // Intercept response
                                    waitForUserInput("INTERCEPTED " + protocol + " RESPONSE (Status: " + status + ")");
                                }
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

        bootstrap.connect(targetHost, targetPort).addListener((ChannelFutureListener) channelListener -> {
            if (!channelListener.isSuccess()) {
                System.out.printf("%s: connect to %s:%d failed: %s%n", protocol, targetHost, targetPort, channelListener.cause());
                sendErrorResponse(ctx, HttpResponseStatus.BAD_GATEWAY);
                return;
            }
            
            Channel origin = channelListener.channel();
            FullHttpRequest forward = new DefaultFullHttpRequest(req.protocolVersion(), req.method(), path, req.content().retain());
            forward.headers().setAll(req.headers());
            
            // Set Host header
            boolean isDefaultPort = (sslContext != null && targetPort == 443) || (sslContext == null && targetPort == 80);
            forward.headers().set(HttpHeaderNames.HOST, targetHost + (isDefaultPort ? "" : ":" + targetPort));
            
            origin.writeAndFlush(forward).addListener(f -> {
                if (!f.isSuccess()) {
                    System.out.printf("%s: write to origin failed: %s%n", protocol, f.cause());
                    sendErrorResponse(ctx, HttpResponseStatus.GATEWAY_TIMEOUT);
                    origin.close();
                }
            });
        });
    }

    private void sendErrorResponse(ChannelHandlerContext ctx, HttpResponseStatus status) {
        // Send an error response and close the connection
        FullHttpResponse failResp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status);
        ctx.writeAndFlush(failResp).addListener(ChannelFutureListener.CLOSE);
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
