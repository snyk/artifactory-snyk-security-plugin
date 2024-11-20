package io.snyk.plugins.artifactory.ecosystem;

import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public enum Ecosystem {

  MAVEN(PluginConfiguration.SCANNER_PACKAGE_TYPE_MAVEN),
  NPM(PluginConfiguration.SCANNER_PACKAGE_TYPE_NPM),
  PYPI(PluginConfiguration.SCANNER_PACKAGE_TYPE_PYPI),
  RUBYGEMS(PluginConfiguration.SCANNER_PACKAGE_TYPE_RUBYGEMS),
  ;

  private static final Logger LOG = LoggerFactory.getLogger(Ecosystem.class);

  private final PluginConfiguration configProperty;

  Ecosystem(PluginConfiguration configProperty) {
    this.configProperty = configProperty;
  }

  public PluginConfiguration getConfigProperty() {
    return configProperty;
  }

  public static Optional<Ecosystem> match(String artifactoryPackageType, String artifactPath) {
    switch (artifactoryPackageType.toLowerCase()) {
      case "maven": return Optional.of(MAVEN);
      case "npm": return Optional.of(NPM);
      case "pypi": return Optional.of(PYPI);
      case "gems": return artifactPath.endsWith(".gem") ? Optional.of(RUBYGEMS) : Optional.empty();
    }

    LOG.info("Unknown package type: {}", artifactoryPackageType);
    return Optional.empty();
  }
}
