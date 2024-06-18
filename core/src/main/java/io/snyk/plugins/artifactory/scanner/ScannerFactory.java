package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykRuntimeException;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.api.rest.SnykRestClient;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.model.NotificationSettings;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;

import java.lang.reflect.Constructor;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.*;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_PACKAGE_TYPE_NUGET;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class ScannerFactory implements AbstractScannerFactory{

  private static final String API_USER_AGENT = "snyk-artifactory-plugin/";
  private static final Logger LOG = LoggerFactory.getLogger(ScannerFactory.class);

  public ScannerFactory() {
  }

  @Override
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

  /*
  Creates a SnykClient to a Snyk scanner
   */
  public SnykClient createSnykClient(@Nonnull ConfigurationModule configurationModule, String pluginVersion, Class client) {
    SnykConfig config = createSnykConfig(configurationModule, pluginVersion);
    SnykClient snykClient;

    try {
      Constructor<?> c = Class.forName(client.getName()).getDeclaredConstructor(config.getClass());
      snykClient = (SnykClient) c.newInstance(config);
      String org = configurationModule.getPropertyOrDefault(API_ORGANIZATION);
      var res = snykClient.getNotificationSettings(org);
      handleResponse(res);
    } catch (Exception e) {
      throw new CannotScanException("Unable to build SnykClient of type: " + client.getName(), e);
    }

    return snykClient;
  }

  private SnykConfig createSnykConfig(@Nonnull ConfigurationModule configurationModule, String pluginVersion) {
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
