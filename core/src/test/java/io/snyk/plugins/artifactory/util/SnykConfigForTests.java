package io.snyk.plugins.artifactory.util;

import io.snyk.sdk.SnykConfig;

public class SnykConfigForTests {
  public static SnykConfig.Builder newBuilder() {
    return SnykConfig.newBuilder()
      .setToken(System.getenv("TEST_SNYK_TOKEN"));
  }

  public static SnykConfig withDefaults() {
    return newBuilder().build();
  }
}
