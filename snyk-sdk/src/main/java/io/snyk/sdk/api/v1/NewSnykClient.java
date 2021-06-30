package io.snyk.sdk.api.v1;

import io.snyk.sdk.Snyk;
import io.snyk.sdk.config.SSLConfiguration;
import io.snyk.sdk.model.NotificationSettings;
import io.snyk.sdk.model.TestResult;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Optional;

public class NewSnykClient {
  private Snyk.Config config;

  private HttpClient httpClient;

  public NewSnykClient(Snyk.Config config) throws Exception {
    this.config = config;

    var builder = HttpClient.newBuilder()
      .version(HttpClient.Version.HTTP_1_1)
      .connectTimeout(Duration.ofSeconds(10));

    // mostly from Snyk.java
    if (config.trustAllCertificates) {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      TrustManager[] trustManagers = SSLConfiguration.buildUnsafeTrustManager();
      sslContext.init(null, trustManagers, new SecureRandom());
      SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
      builder.sslContext(sslContext);
    } else if (config.sslCertificatePath != null && !config.sslCertificatePath.isEmpty()) {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      X509TrustManager trustManager = SSLConfiguration.buildCustomTrustManager(config.sslCertificatePath);
      sslContext.init(null, new TrustManager[]{trustManager}, null);
      SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
      builder.sslContext(sslContext);
    }

    httpClient = builder.build();
  }


  public SnykResult<NotificationSettings> getNotificationSettings(String org) throws java.io.IOException, com.fasterxml.jackson.core.JsonProcessingException, java.lang.InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create()
      .withBaseUrl(config.baseUrl)
      .withPath(String.format("user/me/notification-settings/org/%s", org))
      .withToken(config.token)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, NotificationSettings.class);
  }

  public SnykResult<TestResult> testMaven(String groupId, String artifactId, String version, Optional<String> organisation, Optional<String> repository) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create()
      .withBaseUrl(config.baseUrl)
      .withPath(String.format("test/maven/%s/%s/%s", groupId, artifactId, version))
      .withOptionalQueryParam("org", organisation)
      .withOptionalQueryParam("repository", repository)
      .withToken(config.token)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }

  public SnykResult<TestResult> testNpm(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create()
      .withBaseUrl(config.baseUrl)
      .withPath(String.format("test/npm/%s/%s", packageName, version))
      .withOptionalQueryParam("org", organisation)
      .withToken(config.token)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }

  public SnykResult<TestResult> testRubyGems(String gemName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create()
      .withBaseUrl(config.baseUrl)
      .withPath(String.format("test/rubygems/%s/%s", gemName, version))
      .withOptionalQueryParam("org", organisation)
      .withToken(config.token)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }

  public SnykResult<TestResult> testGradle(String groupId, String artifactId, String version, Optional<String> organisation, Optional<String> repository) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create()
      .withBaseUrl(config.baseUrl)
      .withPath(String.format("test/gradle/%s/%s/%s", groupId, artifactId, version))
      .withOptionalQueryParam("org", organisation)
      .withOptionalQueryParam("repository", repository)
      .withToken(config.token)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }

  public SnykResult<TestResult> testSbt(String groupId, String artifactId, String version, Optional<String> organisation, Optional<String> repository) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create()
      .withBaseUrl(config.baseUrl)
      .withPath(String.format("test/sbt/%s/%s/%s", groupId, artifactId, version))
      .withOptionalQueryParam("org", organisation)
      .withOptionalQueryParam("repository", repository)
      .withToken(config.token)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }

  public SnykResult<TestResult> testPip(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create()
      .withBaseUrl(config.baseUrl)
      .withPath(String.format("test/pip/%s/%s", packageName, version))
      .withOptionalQueryParam("org", organisation)
      .withToken(config.token)
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, TestResult.class);
  }
}
