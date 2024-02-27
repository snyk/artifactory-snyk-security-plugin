package io.snyk.plugins.artifactory;

import io.snyk.plugins.artifactory.audit.AuditModule;
import io.snyk.plugins.artifactory.configuration.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.plugins.artifactory.exception.SnykRuntimeException;
import io.snyk.plugins.artifactory.scanner.ScannerModule;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.api.rest.SnykRestClient;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.NotificationSettings;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.ItemInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.security.User;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.File;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.Optional;
import java.util.Properties;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.*;
import static java.lang.String.format;

public class SnykPlugin {

  private static final Logger LOG = LoggerFactory.getLogger(SnykPlugin.class);
  private static final String API_USER_AGENT = "snyk-artifactory-plugin/";

  private ConfigurationModule configurationModule;
  private AuditModule auditModule;
  private ScannerModule scannerModule;

  SnykPlugin() {
  }

  public SnykPlugin(@Nonnull Repositories repositories, File pluginsDirectory) {
    try {
      LOG.info("Loading and validating plugin properties...");
      Properties properties = PropertyLoader.loadProperties(pluginsDirectory);
      String pluginVersion = PropertyLoader.loadPluginVersion(pluginsDirectory);
      configurationModule = new ConfigurationModule(properties);
      validateConfiguration();

      LOG.info("Creating api client and modules...");
      LOG.info("BaseURL:" + configurationModule.getPropertyOrDefault(API_URL));
      LOG.info("RestBaseURL:" + configurationModule.getPropertyOrDefault(API_REST_URL));
      LOG.info("RestVersion:" + configurationModule.getPropertyOrDefault(API_REST_VERSION));
      LOG.info("Organization:" + configurationModule.getPropertyOrDefault(API_ORGANIZATION));
      String token = configurationModule.getPropertyOrDefault(API_TOKEN);
      if (null != token && token.length() > 4) {
        token = token.substring(0, 4) + "...";
      } else {
        token = "no token configured";
      }
      LOG.debug("Token:" + token);
      final SnykClient snykV1Client = createSnykV1Client(configurationModule, pluginVersion);
      final SnykClient snykRestClient = createSnykRestClient(configurationModule, pluginVersion);

      auditModule = new AuditModule();
      scannerModule = new ScannerModule(configurationModule, repositories, (SnykV1Client) snykV1Client, (SnykRestClient) snykRestClient);

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
    try {
      scannerModule.scanArtifact(repoPath);
    } catch (CannotScanException e) {
      LOG.debug("Artifact cannot be scanned. {} {}", e.getMessage(), repoPath);
    } catch (SnykAPIFailureException e) {
      final String blockOnApiFailurePropertyKey = SCANNER_BLOCK_ON_API_FAILURE.propertyKey();
      final String blockOnApiFailure = configurationModule.getPropertyOrDefault(SCANNER_BLOCK_ON_API_FAILURE);
      final String causeMessage = Optional.ofNullable(e.getCause())
        .map(Throwable::getMessage)
        .map(m -> e.getMessage() + " " + m)
        .orElseGet(e::getMessage);

      String message = format("Artifact scan failed due to an API error on Snyk's side. %s %s", causeMessage, repoPath);
      LOG.debug(message);
      if ("true".equals(blockOnApiFailure)) {
        LOG.debug("Blocking download. Plugin Property \"{}\" is \"true\". {}", blockOnApiFailurePropertyKey, repoPath);
        throw new CancelException(message, 500);
      }
    }
  }

  private void validateConfiguration() {
    try {
      configurationModule.validate();
    } catch (Exception ex) {
      throw new SnykRuntimeException("Snyk Plugin Configuration is not valid!", ex);
    }

    LOG.debug("Snyk Plugin Configuration:");
    configurationModule.getPropertyEntries().stream()
      .filter(entry -> !API_TOKEN.propertyKey().equals(entry.getKey()))
      .filter(entry -> !API_ORGANIZATION.propertyKey().equals(entry.getKey()))
      .map(entry -> entry.getKey() + "=" + entry.getValue())
      .sorted()
      .forEach(LOG::debug);
  }

  private SnykConfig createSnykConfig(@Nonnull ConfigurationModule configurationModule, String pluginVersion) throws Exception {
    final String token = configurationModule.getPropertyOrDefault(API_TOKEN);
    String baseUrl = configurationModule.getPropertyOrDefault(API_URL);
    String restBaseUrl = configurationModule.getPropertyOrDefault(API_REST_URL);
    String restVersion = configurationModule.getPropertyOrDefault(API_REST_VERSION);
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
    if (!restBaseUrl.endsWith("/")) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("'{}' must end in /, your value is '{}'", API_REST_URL.propertyKey(), restBaseUrl);
      }
      restBaseUrl = restBaseUrl + "/";
    }

    String sslCertificatePath = configurationModule.getPropertyOrDefault(API_SSL_CERTIFICATE_PATH);
    String httpProxyHost = configurationModule.getPropertyOrDefault(HTTP_PROXY_HOST);
    Integer httpProxyPort = Integer.parseInt(configurationModule.getPropertyOrDefault(HTTP_PROXY_PORT));
    Duration timeout = Duration.ofMillis(Integer.parseInt(configurationModule.getPropertyOrDefault(API_TIMEOUT)));

    var config = SnykConfig.newBuilder()
      .setBaseUrl(baseUrl)
      .setRestBaseUrl(restBaseUrl)
      .setRestVersion(restVersion)
      .setToken(token)
      .setUserAgent(API_USER_AGENT + pluginVersion)
      .setTrustAllCertificates(trustAllCertificates)
      .setSslCertificatePath(sslCertificatePath)
      .setHttpProxyHost(httpProxyHost)
      .setHttpProxyPort(httpProxyPort)
      .setTimeout(timeout)
      .build();

    LOG.debug("about to log config...");
    LOG.debug("config.httpProxyHost: " + config.httpProxyHost);
    LOG.debug("config.httpProxyPort: " + config.httpProxyPort);

    return config;
  }

  // TODO: refactor with class newInstance()
  private SnykClient createSnykV1Client(@Nonnull ConfigurationModule configurationModule, String pluginVersion) throws Exception {
    SnykConfig config = createSnykConfig(configurationModule, pluginVersion);
    final SnykClient snykV1Client = new SnykV1Client(config);
    String org = configurationModule.getPropertyOrDefault(API_ORGANIZATION);
    var res = snykV1Client.getNotificationSettings(org);
    handleResponse(res);

    return snykV1Client;
  }

  // TODO: refactor with class newInstance()
  private SnykClient createSnykRestClient(@Nonnull ConfigurationModule configurationModule, String pluginVersion) throws Exception {
    SnykConfig config = createSnykConfig(configurationModule, pluginVersion);
    final SnykClient snykRestClient = new SnykRestClient(config);
    String org = configurationModule.getPropertyOrDefault(API_ORGANIZATION);
    var res = snykRestClient.getNotificationSettings(org);
    handleResponse(res);

    return snykRestClient;
  }

  void handleResponse(SnykResult<NotificationSettings> res) {
    if (res.isSuccessful()) {
      LOG.info("Snyk token check successful - response status code {}", res.statusCode);
    } else {
      String info = "";
      if (null != res.response) {
        HttpRequest request = res.response.request();
        info += "\nRequest URI: " + request.uri();
        info += "\nRequest Headers: " + sanitizeHeaders(request);
        info += "\nResponse Status: " + res.response.statusCode();
        info += "\nResponse Body: " + res.response.body();
      }
      LOG.warn("Snyk token check unsuccessful - response status code {}{}", res.statusCode, info);
      if (res.statusCode == 401) {
        throw new SnykRuntimeException(format("%s is not valid.%s", API_TOKEN.propertyKey(), info));
      } else {
        throw new SnykRuntimeException(format("%s could not be verified.%s", API_TOKEN.propertyKey(), info));
      }
    }
  }

  @NotNull
  static String sanitizeHeaders(HttpRequest request) {
    Optional<String> authorization = request.headers().firstValue("Authorization");
    if (authorization.isPresent()) {
      String header = authorization.get();
      if (header.contains("token") && header.length() > 10) {
        String maskedAuthHeader = header.substring(0, 10) + "...";
        return request.headers().toString().replace(header, maskedAuthHeader);
      }
    }
    return request.headers().toString();
  }
}
