package io.snyk.sdk.api.v3;

import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.ApiVersion;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.api.SnykHttpRequestBuilder;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.config.SSLConfiguration;
import io.snyk.sdk.model.v1.Issues;
import io.snyk.sdk.model.v1.NotificationSettings;
import io.snyk.sdk.model.v1.TestResult;
import io.snyk.sdk.model.v3.IssuesResult;
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

public class SnykV3Client extends SnykClient<OrganisationSettings, IssuesResult> {
  private static final String API_VERSION = "2023-06-19";

  public SnykV3Client(SnykConfig config) throws Exception {
    super(config);
  }

  private String generatePurl(Optional<String> organisation, String namespace, String packageName, String version) {
    // https://api.snyk.io/rest/orgs/c7771571-a175-4aba-b6c3-a7d41d217848/packages/pkg%3Apypi%2Furllib3%401.25.7/issues?version=2023-06-19
    // https://api.snyk.io/rest/orgs/c7771571-a175-4aba-b6c3-a7d41d217848/packages/pkg:pypi/urllib3@1.25.7/issues?version=2023-06-19
    String path = String.format("orgs/%s/packages/", organisation.orElseThrow());
    String purl = String.format("pkg:%s/%s@%s", namespace, packageName, version);
    return path + URLEncoder.encode(purl, UTF_8);
  }

  public SnykResult<OrganisationSettings> validateCredentials(String org) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<IssuesResult> testMaven(String groupId, String artifactId, String version, Optional<String> organisation, Optional<String> repository) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<IssuesResult> testNpm(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<IssuesResult> testRubyGems(String gemName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    throw new UnsupportedOperationException("This method is not yet implemented.");
  }

  public SnykResult<IssuesResult> testPip(String packageName, String version, Optional<String> organisation) throws IOException, InterruptedException {
    String path = generatePurl(organisation, Namespace.PYPI.propertyKey(), packageName, version);
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format("%s/issues", path))
      .withQueryParam("version", API_VERSION)
      .build(ApiVersion.V3);
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    return SnykResult.createResult(response, IssuesResult.class);
  }
}
