package io.snyk.sdk.api;

import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.config.SSLConfiguration;
import io.snyk.sdk.model.NotificationSettings;
import io.snyk.sdk.model.TestResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public abstract class SnykClient {
  protected static final Logger LOG = LoggerFactory.getLogger(SnykClient.class);

  protected final SnykConfig config;
  protected final HttpClient httpClient;

  public SnykClient(SnykConfig config) throws Exception {
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

  public SnykResult<NotificationSettings> getNotificationSettings(String org) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format(
        "user/me/notification-settings/org/%s",
        URLEncoder.encode(org, UTF_8)
      ))
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, NotificationSettings.class);
  }
}
