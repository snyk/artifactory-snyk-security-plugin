package io.snyk.sdk.config;

import javax.annotation.Nonnull;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

public final class SSLConfiguration {

  private SSLConfiguration() {
  }

  @Nonnull
  public static TrustManager[] buildUnsafeTrustManager() {
    return new TrustManager[]{
      new X509TrustManager() {
        @SuppressWarnings("squid:S4424")
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String authType) {
        }

        @SuppressWarnings("squid:S4424")
        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
          return new X509Certificate[0];
        }
      }
    };
  }

  @Nonnull
  public static X509TrustManager buildCustomTrustManager(@Nonnull String sslCertificatePath) throws Exception {

    try (InputStream is = Files.newInputStream(Paths.get(sslCertificatePath))) {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(is);

      // create new keystore
      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);

      int certificateEntryIndex = 0;
      for (Certificate certificate : certificates) {
        String certificateAlias = Integer.toString(certificateEntryIndex++);
        keyStore.setCertificateEntry(certificateAlias, certificate);
      }

      KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyManagerFactory.init(keyStore, null);
      TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(keyStore);
      TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
      if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
        throw new RuntimeException("Unexpected default trust managers: " + Arrays.toString(trustManagers));
      } else {
        return (X509TrustManager) trustManagers[0];
      }
    }
  }
}
