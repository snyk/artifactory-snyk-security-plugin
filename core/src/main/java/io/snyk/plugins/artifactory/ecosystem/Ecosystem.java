package io.snyk.plugins.artifactory.ecosystem;

import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public enum Ecosystem {


  MAVEN(PluginConfiguration.SCANNER_PACKAGE_TYPE_MAVEN),
  NPM(PluginConfiguration.SCANNER_PACKAGE_TYPE_NPM),
  PYPI(PluginConfiguration.SCANNER_PACKAGE_TYPE_PYPI),
  ;

  private static final Logger LOG = LoggerFactory.getLogger(Ecosystem.class);

  private final PluginConfiguration configProperty;

  Ecosystem(PluginConfiguration configProperty) {
    this.configProperty = configProperty;
  }

  public PluginConfiguration getConfigProperty() {
    return configProperty;
  }

  public static Optional<Ecosystem> fromPackageType(String artifactoryPackageType) {
    switch (artifactoryPackageType.toLowerCase()) {
      case "maven": return Optional.of(MAVEN);
      case "npm": return Optional.of(NPM);
      case "pypi": return Optional.of(PYPI);
    }

    LOG.error("Unknown package type: {}", artifactoryPackageType);
    return Optional.empty();
  }
}
