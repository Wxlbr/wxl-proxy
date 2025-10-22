package com.wxlbr.wxlproxy.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class CertificateAuthority {
    private static final String PROVIDER = "BC";
    private static final int KEY_SIZE = 2048; // TODO: Increase to 3072 or 4096 for stronger security
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final Path caDir;
    private final PrivateKey caKey;
    private final X509Certificate caCert;
    private final Map<String, X509Certificate> certCache = new ConcurrentHashMap<>();
    private final Map<String, PrivateKey> keyCache = new ConcurrentHashMap<>();

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
                // Load existing keys
                caKey = Pem.readPrivateKey(keyPath);
                caCert = Pem.readCertificate(crtPath);
            } else {
                // Generate new keys
                KeyPair keyPair = generateKeyPair();
                caKey = keyPair.getPrivate();
                caCert = generateCACertificate(keyPair);
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

    public synchronized X509Certificate getOrCreateCertForHost(String hostname) {
        try {
            // Return cached certificate if it exists
            if (certCache.containsKey(hostname)) {
                return certCache.get(hostname);
            }

            // Otherwise, generate a new certificate
            KeyPair keyPair = generateKeyPair();
            X509Certificate cert = generateHostCertificate(hostname, keyPair);
            certCache.put(hostname, cert);
            keyCache.put(hostname, keyPair.getPrivate());
            return cert;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate certificate for " + hostname, e);
        }
    }

    public synchronized PrivateKey getPrivateKeyForHost(String hostname) {
        // Return cached private key if it exists
        return keyCache.get(hostname);
    }

    private static KeyPair generateKeyPair() throws GeneralSecurityException {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    private static X509Certificate generateCACertificate(KeyPair keyPair) throws Exception {
        // Generate the CA certificate (self-signed)
        X500Name issuerName = new X500Name("CN=wxl-proxy Local Root CA, O=wxl-proxy, C=GB");

        JcaX509v3CertificateBuilder builder = createCertificateBuilder(
            issuerName,
            issuerName,
            keyPair.getPublic()
        );

        // CA extensions
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return buildCertificate(builder, keyPair.getPrivate());
    }

    private X509Certificate generateHostCertificate(String hostname, KeyPair keyPair) throws Exception {
        // Generate a hostname certificate signed by the CA
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + hostname + ",O=wxl-proxy,C=GB");

        JcaX509v3CertificateBuilder builder = createCertificateBuilder(
            issuer,
            subject,
            keyPair.getPublic()
        );

        // Host certificate extensions
        builder.addExtension(Extension.subjectKeyIdentifier, false,
            new JcaX509ExtensionUtils().createSubjectKeyIdentifier(
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())));
        builder.addExtension(Extension.subjectAlternativeName, false,
            new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)));
        builder.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.dataEncipherment));

        return buildCertificate(builder, caKey);
    }

    private static JcaX509v3CertificateBuilder createCertificateBuilder(
            X500Name issuer, X500Name subject, PublicKey publicKey) {
        // Helper function to create a certificate builder with common settings
        Date startDate = new Date();
        Date endDate = Date.from(ZonedDateTime.now().plusYears(1).toInstant());
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        return new JcaX509v3CertificateBuilder(
            issuer,
            serialNumber,
            startDate,
            endDate,
            subject,
            publicKey
        );
    }

    private static X509Certificate buildCertificate(
            JcaX509v3CertificateBuilder builder, PrivateKey signingKey) throws Exception {
        // Helper function to build and sign a certificate
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
            .setProvider(PROVIDER)
            .build(signingKey);

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(holder);
    }
}
