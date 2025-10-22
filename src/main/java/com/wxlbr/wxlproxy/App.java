package com.wxlbr.wxlproxy;

import com.wxlbr.wxlproxy.cert.CertificateAuthority;
import com.wxlbr.wxlproxy.proxy.ProxyServer;

public final class App {
    public static void main(String[] args) throws Exception {

        // Default values hardcoded for now
        String host = "127.0.0.1";
        int port = 8080;
        String dataDir = ".wxl";

        System.out.printf("Starting proxy server on %s:%d with data directory %s%n", host, port, dataDir);

        // Create Root CA
        CertificateAuthority ca = CertificateAuthority.create(dataDir);

        // Create Proxy Server
        var proxy = new ProxyServer(host, port, ca);
        
        // CTRL-C shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(proxy::stop));
        
        // Start proxy server
        proxy.start();
    }
}
