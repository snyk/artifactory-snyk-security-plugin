package io.snyk.sdk;

import io.snyk.sdk.Snyk.Config;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SnykClientTest {

  @Test
  void createSnykClient_shouldThrowIAE_ifTokenIsNull() {
    Config config = new Config(null);

    Exception exception = assertThrows(IllegalArgumentException.class, () -> Snyk.newBuilder(config).buildSync());
    assertEquals("Snyk API token is empty", exception.getMessage());
  }

  @Test
  void createSnykConfig_shouldReturnDefaultValues_ifNotDefined() {
    Config config = new Config("snyk-api-token");

    assertEquals("https://api.snyk.io/v1/", config.baseUrl);
    assertEquals("snyk-sdk-java", config.userAgent);
  }

  @Test
  void createSnykConfig_shouldReturnCorrectBaseUrl_IfOverridden() {
    Config config = new Config("https://snyk-on-prem.local", "snyk-api-token");

    assertEquals("https://snyk-on-prem.local", config.baseUrl);
  }
}
