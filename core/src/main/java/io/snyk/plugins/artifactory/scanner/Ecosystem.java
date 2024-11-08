package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.PluginConfiguration;

import java.util.Optional;

public enum Ecosystem {

  MAVEN(PluginConfiguration.SCANNER_PACKAGE_TYPE_MAVEN),
  NPM(PluginConfiguration.SCANNER_PACKAGE_TYPE_NPM),
  PYPI(PluginConfiguration.SCANNER_PACKAGE_TYPE_PYPI),
  COCOAPODS(PluginConfiguration.SCANNER_PACKAGE_TYPE_COCOAPODS),
  NUGET(PluginConfiguration.SCANNER_PACKAGE_TYPE_NUGET),
  GEMS(PluginConfiguration.SCANNER_PACKAGE_TYPE_GEMS),
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

/*
public PackageScanner createScanner(@Nonnull ConfigurationModule configurationModule, @Nonnull Repositories repositories, @Nonnull RepoPath repoPath, String pluginVersion) {
    String path = Optional.ofNullable(repoPath.getPath())
      .orElseThrow(() -> new CannotScanException("Path not provided."));
    RepositoryConfiguration repoConf = repositories.getRepositoryConfiguration(repoPath.getRepoKey());
    String packageType = requireNonNull(repoConf).getPackageType();
    SnykV1Client v1Client = (SnykV1Client) createSnykClient(configurationModule, pluginVersion, SnykV1Client.class);
    SnykRestClient restClient = (SnykRestClient) createSnykClient(configurationModule, pluginVersion, SnykRestClient.class);
    LOG.debug(format("Snyk determining scanner for packageType: %s, path: " + packageType, path));

    if (path.endsWith(".jar")) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_MAVEN).equals("true")) {
        return new MavenScanner(configurationModule, v1Client);
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_MAVEN.propertyKey()));
    } else if (path.endsWith(".tgz")) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_NPM).equals("true")) {
        return new NpmScanner(configurationModule, v1Client);
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_NPM.propertyKey()));
    } else if (packageType.equalsIgnoreCase("pypi") && (path.endsWith(".whl") || path.endsWith(".tar.gz") || path.endsWith(".zip") || path.endsWith(".egg"))) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_PYPI).equals("true")) {
        return new PythonScanner(configurationModule, v1Client);
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_PYPI.propertyKey()));
    } else if (packageType.equalsIgnoreCase("cocoapods") && (path.endsWith(".tar.gz") || path.endsWith(".zip"))) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_COCOAPODS).equals("true")) {
        LOG.debug("Snyk launching cocoapods scanner");
        return new PurlScanner(configurationModule, repositories, restClient);
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_COCOAPODS.propertyKey()));
    } else if (path.endsWith(".nupkg")) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_NUGET).equals("true")) {
        LOG.debug("Snyk launching nuget scanner");
        return new PurlScanner(configurationModule, repositories, restClient);
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_NUGET.propertyKey()));
    } else if (path.endsWith(".gem")) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_GEMS).equals("true")) {
        LOG.debug("Snyk launching gems scanner");
        return new PurlScanner(configurationModule, repositories, restClient);
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_GEMS.propertyKey()));
    }

    throw new CannotScanException("Artifact is not supported.");
  }

 */
