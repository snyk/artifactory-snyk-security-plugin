package io.snyk.plugins.artifactory.configuration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_TOKEN;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_URL;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_LICENSE_THRESHOLD;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("PluginConfiguration")
class PluginConfigurationTest {

  @DisplayName("check default values")
  @Test
  void checkDefaultValues() {
    assertAll("should be not empty",
              () -> assertEquals("https://snyk.io/api/v1/", API_URL.defaultValue(), getAssertionMessage(API_URL, "default value must be 'https://snyk.io/api/v1/'")),
              () -> assertEquals("low", SCANNER_VULNERABILITY_THRESHOLD.defaultValue(), getAssertionMessage(SCANNER_VULNERABILITY_THRESHOLD, "default value must be 'low'")),
              () -> assertEquals("low", SCANNER_LICENSE_THRESHOLD.defaultValue(), getAssertionMessage(SCANNER_LICENSE_THRESHOLD, "default value must be 'low'"))
    );

    assertAll("should be empty",
              () -> assertEquals("", API_TOKEN.defaultValue(), getAssertionMessage(API_TOKEN, "default value must be empty")),
              () -> assertEquals("", API_ORGANIZATION.defaultValue(), getAssertionMessage(API_ORGANIZATION, "default value must be empty"))
    );
  }

  private String getAssertionMessage(Configuration entry, String message) {
    return String.format("'%s' %s", entry.propertyKey(), message);
  }
}
