package io.snyk.plugins.artifactory;

import io.snyk.plugins.artifactory.audit.AuditModule;
import io.snyk.plugins.artifactory.configuration.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.SnykRuntimeException;
import io.snyk.plugins.artifactory.scanner.ScannerModule;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import org.artifactory.fs.ItemInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.security.User;
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
  private final AuditModule auditModule;
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

      auditModule = new AuditModule();
      scannerModule = new ScannerModule(configurationModule, repositories, snykClient);

      LOG.info("Plugin version: {}", pluginVersion);
    } catch (Exception ex) {
      throw new SnykRuntimeException("Snyk plugin could not be initialized!", ex);
    }
  }

  /**
   * Logs update event for following artifact properties:
   * <ul>
   * <li>{@link ArtifactProperty#ISSUE_LICENSES_FORCE_DOWNLOAD}</li>
   * <li>{@link ArtifactProperty#ISSUE_LICENSES_FORCE_DOWNLOAD_INFO}</li>
   * <li>{@link ArtifactProperty#ISSUE_VULNERABILITIES_FORCE_DOWNLOAD}</li>
   * <li>{@link ArtifactProperty#ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO}</li>
   * </ul>
   * <p>
   * Extension point: {@code storage.afterPropertyCreate}.
   */
  public void handleAfterPropertyCreateEvent(User user, ItemInfo itemInfo, String propertyName, String[] propertyValues) {
    LOG.debug("Handle 'afterPropertyCreate' event for: {}", itemInfo);
    auditModule.logPropertyUpdate(user, itemInfo, propertyName, propertyValues);
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

    var config = new Snyk.Config(baseUrl, token, API_USER_AGENT + pluginVersion, trustAllCertificates, sslCertificatePath);
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
