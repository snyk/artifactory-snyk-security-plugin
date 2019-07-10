package io.snyk.plugins.artifactory.configuration;

import javax.annotation.Nonnull;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_TOKEN;
import static java.lang.String.format;

public class ConfigurationModule {

  private final Properties properties;

  public ConfigurationModule(@Nonnull Properties properties) {
    this.properties = properties;
  }

  public Set<Map.Entry<Object, Object>> getPropertyEntries() {
    return new HashSet<>(properties.entrySet());
  }

  public String getProperty(Configuration config) {
    return properties.getProperty(config.propertyKey());
  }

  public String getPropertyOrDefault(Configuration config) {
    return properties.getProperty(config.propertyKey(), config.defaultValue());
  }

  public void validate() {
    final String apiToken = getProperty(API_TOKEN);
    if (apiToken == null || apiToken.isEmpty()) {
      throw new IllegalArgumentException(format("'%s' must not be null or empty", API_TOKEN.propertyKey()));
    }

    final String apiOrganization = getProperty(API_ORGANIZATION);
    if (apiOrganization == null || apiOrganization.isEmpty()) {
      throw new IllegalArgumentException(format("'%s' must not be null or empty", API_ORGANIZATION.propertyKey()));
    }
  }
}
