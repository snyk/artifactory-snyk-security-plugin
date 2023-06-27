package io.snyk.sdk.api.v3;

import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.config.SSLConfiguration;
import io.snyk.sdk.model.v1.NotificationSettings;
import io.snyk.sdk.model.v1.TestResult;
import io.snyk.sdk.model.v3.OrganisationSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.util.Optional;

public class SnykV3Client {
  private static final Logger LOG = LoggerFactory.getLogger(SnykV3Client.class);

  private final SnykConfig config;
  private final HttpClient httpClient;

  public SnykV3Client(SnykConfig config) throws Exception {
    this.config = config;

    var builder = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(config.timeout);

    if (config.trustAllCertificates) {
      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      TrustManager[] trustManagers = SSLConfiguration.buildUnsafeTrustManager();
      sslContext.init(null, trustManagers, new SecureRandom());
      builder.sslContext(sslContext);
    } else if (config.sslCertificatePath != null && !config.sslCertificatePath.isEmpty()) {
      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      X509TrustManager trustManager = SSLConfiguration.buildCustomTrustManager(config.sslCertificatePath);
      sslContext.init(null, new TrustManager[]{trustManager}, null);
      builder.sslContext(sslContext);
    }

    if (!config.httpProxyHost.isBlank()) {
      builder.proxy(ProxySelector.of(new InetSocketAddress(config.httpProxyHost, config.httpProxyPort)));
      LOG.info("added proxy with ", config.httpProxyHost, config.httpProxyPort);
    }

    httpClient = builder.build();
  }

  public SnykResult<OrganisationSettings> validateCredentials(String org) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<TestResult> testMaven(String groupId, String artifactId, String version, Optional<String> organisation, Optional<String> repository) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");

  }

  public SnykResult<TestResult> testNpm(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");

  }

  public SnykResult<TestResult> testRubyGems(String gemName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");

  }

  public SnykResult<TestResult> testPip(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");

  }
}
