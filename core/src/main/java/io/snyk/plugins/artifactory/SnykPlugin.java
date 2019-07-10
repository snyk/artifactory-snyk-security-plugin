package io.snyk.plugins.artifactory;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.util.Properties;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.SnykRuntimeException;
import io.snyk.plugins.artifactory.scanner.ScannerModule;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_TOKEN;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_URL;

public class SnykPlugin {

  private static final Logger LOG = LoggerFactory.getLogger(SnykPlugin.class);

  private final ConfigurationModule configurationModule;
  private final ScannerModule scannerModule;

  public SnykPlugin(@Nonnull Repositories repositories, File pluginsDirectory) {
    try {
      //load and validate plugin properties
      Properties properties = PropertyLoader.loadProperties(pluginsDirectory);
      configurationModule = new ConfigurationModule(properties);
      validateConfiguration();

      //create api client and modules
      final SnykClient snykClient = createSnykClient(configurationModule);
      scannerModule = new ScannerModule(configurationModule, repositories, snykClient);
    } catch (IOException ex) {
      throw new SnykRuntimeException("Snyk plugin could not be initialized!", ex);
    }
  }

  /**
   * Scans an artifact for issues (vulnerability or license).
   * <p>
   * Extension point: {@code download.beforeDownload}.
   */
  public void handleBeforeDownloadEvent(RepoPath repoPath) {
    LOG.debug("Handle 'beforeDownload' event for: {}", repoPath);
    scannerModule.scanArtifact(repoPath);
  }

  private void validateConfiguration() {
    LOG.info("Validate Snyk plugin configuration");
    try {
      configurationModule.validate();
    } catch (Exception ex) {
      throw new SnykRuntimeException("Snyk plugin configuration is not valid!", ex);
    }

    LOG.debug("Snyk plugin configuration:");
    configurationModule.getPropertyEntries().stream()
                       .filter(entry -> !API_TOKEN.propertyKey().equals(entry.getKey()))
                       .filter(entry -> !API_ORGANIZATION.propertyKey().equals(entry.getKey()))
                       .map(entry -> entry.getKey() + "=" + entry.getValue())
                       .sorted()
                       .forEach(LOG::debug);
  }

  @Nonnull
  private SnykClient createSnykClient(ConfigurationModule configurationModule) {
    String baseUrl = configurationModule.getPropertyOrDefault(API_URL);
    if (!baseUrl.endsWith("/")) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("'{}' must end in /, your value is '{}'", API_URL.propertyKey(), baseUrl);
      }
      baseUrl = baseUrl + "/";
    }
    final String token = configurationModule.getPropertyOrDefault(API_TOKEN);

    return Snyk.newBuilder(new Snyk.Config(baseUrl, token)).buildSync();
  }
}
