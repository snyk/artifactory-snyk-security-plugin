package io.snyk.sdk.api.v1;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URLEncoder;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.config.SSLConfiguration;
import io.snyk.sdk.model.NotificationSettings;
import io.snyk.sdk.model.TestResult;

public class SnykClient {
  private static final Logger LOG = LoggerFactory.getLogger(SnykClient.class);

  private final SnykConfig config;
  private final HttpClient httpClient;

  public SnykClient(SnykConfig config) throws Exception {
    this.config = config;

    var builder = HttpClient.newBuilder()
      .version(HttpClient.Version.HTTP_1_1)
      .connectTimeout(config.timeout);

    if (config.trustAllCertificates) {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      TrustManager[] trustManagers = SSLConfiguration.buildUnsafeTrustManager();
      sslContext.init(null, trustManagers, new SecureRandom());
      builder.sslContext(sslContext);
    } else if (config.sslCertificatePath != null && !config.sslCertificatePath.isEmpty()) {
      SSLContext sslContext = SSLContext.getInstance("TLS");
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

  public SnykResult<NotificationSettings> getNotificationSettings(String org) throws java.io.IOException, java.lang.InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format(
        "user/me/notification-settings/org/%s",
        URLEncoder.encode(org, UTF_8)
      ))
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, NotificationSettings.class);
  }

  public SnykResult<TestResult> testMaven(String groupId, String artifactId, String version, Optional<String> organisation, Optional<String> repository) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format(
        "test/maven/%s/%s/%s",
        URLEncoder.encode(groupId, UTF_8),
        URLEncoder.encode(artifactId, UTF_8),
        URLEncoder.encode(version, UTF_8)
      ))
      .withQueryParam("org", organisation)
      .withQueryParam("repository", repository)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }

  public SnykResult<TestResult> testNpm(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format(
        "test/npm/%s/%s",
        URLEncoder.encode(packageName, UTF_8),
        URLEncoder.encode(version, UTF_8)
      ))
      .withQueryParam("org", organisation)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }

  public SnykResult<TestResult> testRubyGems(String gemName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format(
        "test/rubygems/%s/%s",
        URLEncoder.encode(gemName, UTF_8),
        URLEncoder.encode(version, UTF_8)
      ))
      .withQueryParam("org", organisation)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }

  public SnykResult<TestResult> testPip(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format(
        "test/pip/%s/%s",
        URLEncoder.encode(packageName, UTF_8),
        URLEncoder.encode(version, UTF_8)
      ))
      .withQueryParam("org", organisation)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }
}
