package io.snyk.plugins.artifactory.util;

import io.snyk.sdk.SnykConfig;

import java.util.Optional;

public class SnykConfigForTests {
  public static SnykConfig.Builder newBuilder() {
    String token = System.getenv("TEST_SNYK_TOKEN");
    String baseUrl = Optional.ofNullable(System.getenv("TEST_SNYK_BASE_URL")).orElse("https://snyk.io/api/v1/");

    return SnykConfig.newBuilder()
      .setToken(token)
      .setV1BaseUrl(baseUrl);
  }

  public static SnykConfig withDefaults() {
    return newBuilder().build();
  }
}
