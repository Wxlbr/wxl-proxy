package com.wxlbr.wxlproxy.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;

public final class CertificateAuthority {
    private static final String PROVIDER = "BC";
    private final Path caDir;
    private final PrivateKey caKey;
    private final X509Certificate caCert;

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CertificateAuthority(Path caDir, PrivateKey caKey, X509Certificate caCert) {
        this.caDir = caDir;
        this.caKey = caKey;
        this.caCert = caCert;
    }

    public static CertificateAuthority create(String dataDir) {
        try {
            Path dir = Paths.get(dataDir).toAbsolutePath();
            Files.createDirectories(dir);
            Path keyPath = dir.resolve("rootCA.key");
            Path crtPath = dir.resolve("rootCA.crt");

            PrivateKey caKey;
            X509Certificate caCert;

            if (Files.exists(keyPath) && Files.exists(crtPath)) {

                // Load keys
                caKey = Pem.readPrivateKey(keyPath);
                caCert = Pem.readCertificate(crtPath);
            } else {

                // Generate new keys
                KeyPair keyPair = generateKeyPair();
                caKey = keyPair.getPrivate();
                caCert = generateSelfSignedCertificate(keyPair);
                Pem.writePrivateKey(keyPath, caKey);
                Pem.writeCertificate(crtPath, caCert);
                System.out.printf("Created new Root CA at %s%n", dir);
            }

            return new CertificateAuthority(dir, caKey, caCert);

        } catch (Exception e) {
            throw new RuntimeException("Failed to create Certificate Authority", e);
        }
    }

    public PrivateKey caKey() { 
        return caKey; 
    }

    public X509Certificate caCert() {
         return caCert; 
    }

    public Path caDir() { 
        return caDir; 
    }

    private static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // TODO: Increase to 3072 or 4096 for stronger security, 2048 keysize for testing
        return keyGen.generateKeyPair();
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        Date startDate = new Date();
        Date endDate = Date.from(ZonedDateTime.now().plusYears(1).toInstant()); // 1 year expiration, may increase when stable
        X500Name issuerName = new X500Name("CN=wxl-proxy Local Root CA, O=wxl-proxy, C=GB");

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName,
                new BigInteger(64, new SecureRandom()),
                startDate,
                endDate,
                issuerName,
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(PROVIDER)
                .build(keyPair.getPrivate());

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(PROVIDER)
                .getCertificate(holder);
    }
}
