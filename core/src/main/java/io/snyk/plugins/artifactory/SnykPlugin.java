package io.snyk.plugins.artifactory;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.plugins.artifactory.exception.SnykRuntimeException;
import io.snyk.plugins.artifactory.scanner.ScannerModule;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import org.artifactory.exception.CancelException;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.Properties;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.*;

public class SnykPlugin {

  private static final Logger LOG = LoggerFactory.getLogger(SnykPlugin.class);
  private static final String API_USER_AGENT = "snyk-artifactory-plugin/";

  private final ConfigurationModule configurationModule;
  private final ScannerModule scannerModule;

  public SnykPlugin(@Nonnull Repositories repositories, File pluginsDirectory) {
    try {
      LOG.info("Loading and validating plugin properties...");
      Properties properties = PropertyLoader.loadProperties(pluginsDirectory);
      String pluginVersion = PropertyLoader.loadPluginVersion(pluginsDirectory);
      configurationModule = new ConfigurationModule(properties);
      validateConfiguration();

      LOG.info("Creating api client and modules...");

      final SnykClient snykClient = createSnykClient(configurationModule, pluginVersion);

      scannerModule = new ScannerModule(configurationModule, repositories, snykClient);

      LOG.info("Plugin version: {}", pluginVersion);
    } catch (Exception ex) {
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
    try {
      scannerModule.scanArtifact(repoPath);
    } catch (CannotScanException e) {
      LOG.warn("Artifact cannot be scanned {}. {}", repoPath, e.getMessage());
    } catch (SnykAPIFailureException e) {
      final String blockOnApiFailurePropertyKey = SCANNER_BLOCK_ON_API_FAILURE.propertyKey();
      final String blockOnApiFailure = configurationModule.getPropertyOrDefault(SCANNER_BLOCK_ON_API_FAILURE);
      String message = "Failed to scan artifact '" + repoPath + "'. " + e.getMessage();
      if ("true".equals(blockOnApiFailure)) {
        throw new CancelException(message, e, 500);
      }
      LOG.warn(message, e);
      LOG.debug("Property '{}' is false, so allowing download: '{}'", blockOnApiFailurePropertyKey, repoPath);
    }
  }

  private void validateConfiguration() {
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

  private SnykClient createSnykClient(@Nonnull ConfigurationModule configurationModule, String pluginVersion) throws Exception {
    final String token = configurationModule.getPropertyOrDefault(API_TOKEN);
    String baseUrl = configurationModule.getPropertyOrDefault(API_URL);
    boolean trustAllCertificates = false;
    String trustAllCertificatesProperty = configurationModule.getPropertyOrDefault(API_TRUST_ALL_CERTIFICATES);
    if ("true".equals(trustAllCertificatesProperty)) {
      trustAllCertificates = true;
    }

    if (!baseUrl.endsWith("/")) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("'{}' must end in /, your value is '{}'", API_URL.propertyKey(), baseUrl);
      }
      baseUrl = baseUrl + "/";
    }

    String sslCertificatePath = configurationModule.getPropertyOrDefault(API_SSL_CERTIFICATE_PATH);
    String httpProxyHost = configurationModule.getPropertyOrDefault(HTTP_PROXY_HOST);
    Integer httpProxyPort = Integer.parseInt(configurationModule.getPropertyOrDefault(HTTP_PROXY_PORT));

    var config = new Snyk.Config(baseUrl, token, API_USER_AGENT + pluginVersion, trustAllCertificates, sslCertificatePath, httpProxyHost, httpProxyPort);
    LOG.debug("about to log config...");
    LOG.debug("config.httpProxyHost: " + config.httpProxyHost);
    LOG.debug("config.httpProxyPort: " + config.httpProxyPort);

    final SnykClient snykClient = new SnykClient(config);

    String org = configurationModule.getPropertyOrDefault(API_ORGANIZATION);
    var res = snykClient.getNotificationSettings(org);
    if (res.isSuccessful()) {
      LOG.info("Snyk token check successful - response status code {}", res.statusCode);
    } else {
      LOG.warn("Snyk token check unsuccessful - response status code {}", res.statusCode);
      if (res.statusCode == 401) {
        throw new SnykRuntimeException("Invalid 'snyk.api.token' provided");
      } else {
        throw new SnykRuntimeException("Error verifying Snyk token");
      }
    }

    return snykClient;
  }
}
