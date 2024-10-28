package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.PluginConfiguration;

import java.util.Optional;

public enum Ecosystem {

  MAVEN(PluginConfiguration.SCANNER_PACKAGE_TYPE_MAVEN),
  NPM(PluginConfiguration.SCANNER_PACKAGE_TYPE_NPM),
  PYPI(PluginConfiguration.SCANNER_PACKAGE_TYPE_PYPI),
  ;

  private final PluginConfiguration configProperty;

  Ecosystem(PluginConfiguration configProperty) {
    this.configProperty = configProperty;
  }

  public PluginConfiguration getConfigProperty() {
    return configProperty;
  }

  static Optional<Ecosystem> fromPackagePath(String path) {
    if (path.endsWith(".jar")) {
      return Optional.of(MAVEN);
    }

    if (path.endsWith(".tgz")) {
      return Optional.of(NPM);
    }

    if (path.endsWith(".whl") || path.endsWith(".tar.gz") || path.endsWith(".zip") || path.endsWith(".egg")) {
      return Optional.of(PYPI);
    }

    return Optional.empty();
  }
}
