package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.model.v1.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

import java.net.URLEncoder;
import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.slf4j.LoggerFactory.getLogger;

class MavenScanner implements PackageScanner {

  private static final Logger LOG = getLogger(MavenScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykV1Client snykV1Client;

  MavenScanner(ConfigurationModule configurationModule, SnykV1Client snykV1Client) {
    this.configurationModule = configurationModule;
    this.snykV1Client = snykV1Client;
  }

  public static String getArtifactDetailsURL(String groupID, String artifactID, String artifactVersion) {
    return "https://snyk.io/vuln/" + URLEncoder.encode("maven:" + groupID + ":" + artifactID + "@" + artifactVersion, UTF_8);
  }

  public TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    String groupID = Optional.ofNullable(fileLayoutInfo.getOrganization())
      .orElseThrow(() -> new CannotScanException("Group ID not provided."));
    String artifactID = Optional.ofNullable(fileLayoutInfo.getModule())
      .orElseThrow(() -> new CannotScanException("Artifact ID not provided."));
    String artifactVersion = Optional.ofNullable(fileLayoutInfo.getBaseRevision())
      .orElseThrow(() -> new CannotScanException("Artifact Version not provided."));

    SnykResult<TestResult> result;
    try {
      result = snykV1Client.testMaven(
        groupID,
        artifactID,
        artifactVersion,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION)),
        Optional.empty()
      );
    } catch (Exception e) {
      throw new SnykAPIFailureException(e);
    }

    TestResult testResult = result.get().orElseThrow(() -> new SnykAPIFailureException(result));
    testResult.setPackageDetailsUrl(getArtifactDetailsURL(groupID, artifactID, artifactVersion));
    return testResult;
  }
}
