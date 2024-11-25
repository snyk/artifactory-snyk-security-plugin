package io.snyk.plugins.artifactory.scanner.purl;

import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.TestResultConverter;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.purl.PurlIssues;
import org.slf4j.Logger;

import java.net.URLEncoder;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.slf4j.LoggerFactory.getLogger;

public class PurlScanner {

  private static final Logger LOG = getLogger(PurlScanner.class);

  private final SnykClient snykClient;
  private final String orgId;

  public PurlScanner(SnykClient snykClient, String orgId) {
    this.snykClient = snykClient;
    this.orgId = orgId;
  }

  public TestResult scan(String purl, String packageDetailsUrl) {
    SnykResult<PurlIssues> result;
    try {
      LOG.debug("Running Snyk test: {}", packageDetailsUrl);
      result = snykClient.get(PurlIssues.class, request ->
        request
          .withPath(String.format("rest/orgs/%s/packages/%s/issues",
            URLEncoder.encode(orgId, UTF_8),
            URLEncoder.encode(purl, UTF_8))
          )
          .withQueryParam("version", "2024-10-15")
      );
    } catch (Exception e) {
      throw new SnykAPIFailureException(e);
    }

    PurlIssues testResult = result.get().orElseThrow(() -> new SnykAPIFailureException(result));
    testResult.packageDetailsUrl = packageDetailsUrl;

    return TestResultConverter.convert(testResult);
  }

}
