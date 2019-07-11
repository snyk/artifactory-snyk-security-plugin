package io.snyk.plugins.artifactory.configuration;

import java.util.Properties;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_TOKEN;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConfigurationModuleTest {

  private static Properties PROPERTIES;

  @BeforeAll
  static void setUpAll() {
    PROPERTIES = new Properties();
  }

  @Test
  void validate_shouldThrowSPE_ifApiTokenIsEmptyOrNull() {
    PROPERTIES.put(API_TOKEN.propertyKey(), "");
    PROPERTIES.put(API_ORGANIZATION.propertyKey(), "my-api-organization");
    ConfigurationModule configurationModule = new ConfigurationModule(PROPERTIES);

    assertThrows(IllegalArgumentException.class, configurationModule::validate);
  }

  @Test
  void validate_shouldThrowSPE_ifApiOrganizationIsEmptyOrNull() {
    PROPERTIES.put(API_TOKEN.propertyKey(), "my-api-token");
    PROPERTIES.put(API_ORGANIZATION.propertyKey(), "");
    ConfigurationModule configurationModule = new ConfigurationModule(PROPERTIES);

    assertThrows(IllegalArgumentException.class, configurationModule::validate);
  }
}
