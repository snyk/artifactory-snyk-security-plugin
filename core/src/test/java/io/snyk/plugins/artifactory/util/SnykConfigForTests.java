package io.snyk.plugins.artifactory.util;

import io.snyk.sdk.SnykConfig;

import java.util.Optional;

public class SnykConfigForTests {
  public static SnykConfig.Builder newBuilder() {
    String token = System.getenv("TEST_SNYK_TOKEN");
    String baseUrlV1 = Optional.ofNullable(System.getenv("TEST_SNYK_BASE_URL_V1")).orElse("https://snyk.io/api/v1/");
    String baseUrlV3 = Optional.ofNullable(System.getenv("TEST_SNYK_BASE_URL_V3")).orElse("https://api.snyk.io/rest/");

    return SnykConfig.newBuilder()
      .setToken(token)
      .setV1BaseUrl(baseUrlV1)
      .setV3BaseUrl(baseUrlV3);
  }

  public static SnykConfig withDefaults() {
    return newBuilder().build();
  }
}
