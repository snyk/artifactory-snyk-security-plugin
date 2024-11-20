package io.snyk.plugins.artifactory.scanner.rubygems;

import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.PackageScanner;
import io.snyk.plugins.artifactory.scanner.SnykDetailsUrl;
import io.snyk.plugins.artifactory.scanner.TestResultConverter;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.purl.PurlIssues;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

import java.net.URLEncoder;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.slf4j.LoggerFactory.getLogger;

public class RubyGemsScanner implements PackageScanner {

  private static final Logger LOG = getLogger(RubyGemsScanner.class);
  private final SnykClient snykClient;
  private final String orgId;

  public RubyGemsScanner(SnykClient snykClient, String orgId) {
    this.snykClient = snykClient;
    this.orgId = orgId;
  }

  @Override
  public TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    RubyGemsPackage pckg = RubyGemsPackage.parse(repoPath.getName())
      .orElseThrow(() -> new CannotScanException("Unexpected Ruby Gems package name: " + repoPath.getName()));

    String purl = "pkg:gem/" + pckg.getName() + "@" + pckg.getVersion();

    SnykResult<PurlIssues> result;
    try {
      LOG.debug("Running Snyk test: {}, name: {}, version: {}", repoPath, pckg.getName(), pckg.getVersion());
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
    testResult.packageDetailsUrl = getModuleDetailsURL(pckg.getName(), pckg.getVersion());

    return TestResultConverter.convert(testResult);
  }

  public static String getModuleDetailsURL(String name, String version) {
    return SnykDetailsUrl.create("rubygems", name, version).toString();
  }
}
