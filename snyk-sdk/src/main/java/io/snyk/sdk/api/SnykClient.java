package io.snyk.sdk.api;

import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.v1.SnykResult;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.config.SSLConfiguration;
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

public abstract class SnykClient<T, U> {
  protected static final Logger LOG = LoggerFactory.getLogger(SnykV1Client.class);

  protected final SnykConfig config;
  protected final HttpClient httpClient;

  protected SnykClient(SnykConfig config) throws Exception {
    this.config = config;

    var builder = HttpClient.newBuilder()
      .version(HttpClient.Version.HTTP_1_1)
      .connectTimeout(config.timeout);

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

  public abstract SnykResult<T> getNotificationSettings(String org) throws java.io.IOException, java.lang.InterruptedException;

  public abstract SnykResult<U> testMaven(String groupId, String artifactId, String version, Optional<String> organisation, Optional<String> repository) throws IOException, InterruptedException;

  public abstract SnykResult<U> testNpm(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException;

  public abstract SnykResult<U> testRubyGems(String gemName, String version, Optional<String> organisation) throws IOException, InterruptedException;

  public abstract SnykResult<U> testPip(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException;
}
