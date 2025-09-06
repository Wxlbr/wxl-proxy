package com.wxlbr.wxlproxy.cert;

import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public final class Pem {

    public static void writePrivateKey(Path path, PrivateKey key) throws Exception {
        try (var writer = new JcaPEMWriter(Files.newBufferedWriter(path))) {
            writer.writeObject(key);
        }
    }

    public static void writeCertificate(Path path, X509Certificate cert) throws Exception {
        try (var writer = new JcaPEMWriter(Files.newBufferedWriter(path))) {
            writer.writeObject(cert);
        }
    }

    public static PrivateKey readPrivateKey(Path path) throws Exception {
        try (Reader reader = Files.newBufferedReader(path);
             PEMParser parser = new PEMParser(reader)) {

            Object obj = parser.readObject();
            var conv = new JcaPEMKeyConverter().setProvider("BC");
            
            // PKCS#1
            if (obj instanceof PEMKeyPair keyPair) {
                return conv.getPrivateKey(keyPair.getPrivateKeyInfo());
            }

            // PKCS#8
            if (obj instanceof PrivateKeyInfo privateKeyInfo) {
                return conv.getPrivateKey(privateKeyInfo);
            }

            throw new IllegalArgumentException("Unsupported key format");
        }
    }

    public static X509Certificate readCertificate(Path path) throws Exception {
        try (var in = Files.newInputStream(path, StandardOpenOption.READ)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(in);
        }
    }
}
