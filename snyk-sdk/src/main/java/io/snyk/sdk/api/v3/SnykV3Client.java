package io.snyk.sdk.api.v3;

import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.ApiVersion;
import io.snyk.sdk.api.SnykHttpRequestBuilder;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.config.SSLConfiguration;
import io.snyk.sdk.model.v1.NotificationSettings;
import io.snyk.sdk.model.v1.TestResult;
import io.snyk.sdk.model.v3.Issues;
import io.snyk.sdk.model.v3.OrganisationSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

enum Namespace {
  PYPI("pypi");

  private final String propertyKey;

  Namespace(String propertyKey) {
    this.propertyKey = propertyKey;
  }

  public String propertyKey() {
    return propertyKey;
  }
}

public class SnykV3Client {
  private static final String API_VERSION = "2023-06-19";

  private static final Logger LOG = LoggerFactory.getLogger(SnykV3Client.class);

  private final SnykConfig config;
  private final HttpClient httpClient;

  public SnykV3Client(SnykConfig config) throws Exception {
    this.config = config;

    var builder = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(config.timeout);

    if (config.trustAllCertificates) {
      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      TrustManager[] trustManagers = SSLConfiguration.buildUnsafeTrustManager();
      sslContext.init(null, trustManagers, new SecureRandom());
      builder.sslContext(sslContext);
    } else if (config.sslCertificatePath != null && !config.sslCertificatePath.isEmpty()) {
      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      X509TrustManager trustManager = SSLConfiguration.buildCustomTrustManager(config.sslCertificatePath);
      sslContext.init(null, new TrustManager[]{trustManager}, null);
      builder.sslContext(sslContext);
    }

    if (!config.httpProxyHost.isBlank()) {
      builder.proxy(ProxySelector.of(new InetSocketAddress(config.httpProxyHost, config.httpProxyPort)));
      LOG.info("added proxy with ", config.httpProxyHost, config.httpProxyPort);
    }

    httpClient = builder.build();
  }

  private String generatePurl(Optional<String> organisation, String namespace, String packageName, String version) {
    // https://api.snyk.io/rest/orgs/c7771571-a175-4aba-b6c3-a7d41d217848/packages/pkg%3Apypi%2Furllib3%401.25.7/issues?version=2023-06-19
    // https://api.snyk.io/rest/orgs/c7771571-a175-4aba-b6c3-a7d41d217848/packages/pkg:pypi/urllib3@1.25.7/issues?version=2023-06-19
    String path = String.format("orgs/%s/packages/", organisation.orElseThrow());
    String purl = String.format("pkg:%s/%s@%s/issues?=%s", namespace, packageName, version, API_VERSION);
    return path + URLEncoder.encode(purl, UTF_8);
  }

  public SnykResult<OrganisationSettings> validateCredentials(String org) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<Issues> testMaven(String groupId, String artifactId, String version, Optional<String> organisation, Optional<String> repository) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<Issues> testNpm(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<Issues> testRubyGems(String gemName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<Issues> testPip(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    String path = generatePurl(organisation, Namespace.PYPI.propertyKey(), packageName, version);
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(path)
      .build(ApiVersion.V3);
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, Issues.class);
  }
}
