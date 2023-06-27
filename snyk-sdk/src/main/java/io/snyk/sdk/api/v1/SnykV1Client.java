package io.snyk.sdk.api.v1;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

import io.snyk.sdk.api.SnykClient;

import static java.nio.charset.StandardCharsets.UTF_8;

import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykHttpRequestBuilder;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.v1.NotificationSettings;
import io.snyk.sdk.model.v1.TestResult;

public class SnykV1Client extends SnykClient<NotificationSettings, TestResult> {
  public SnykV1Client(SnykConfig config) throws Exception {
    super(config);
  }

  @Override
  public SnykResult<NotificationSettings> validateCredentials(String org) throws java.io.IOException, java.lang.InterruptedException {
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format(
        "user/me/notification-settings/org/%s",
        URLEncoder.encode(org, UTF_8)
      ))
      .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, NotificationSettings.class);
  }

  @Override
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
