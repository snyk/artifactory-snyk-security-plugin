package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.TestResult;
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
  private final SnykClient snykClient;

  MavenScanner(ConfigurationModule configurationModule, SnykClient snykClient) {
    this.configurationModule = configurationModule;
    this.snykClient = snykClient;
  }

  public static String getArtifactDetailsURL(String groupID, String artifactID, String artifactVersion) {
    return SnykDetailsUrl.create("maven", groupID + ":" + artifactID, artifactVersion).toString();
  }

  public io.snyk.plugins.artifactory.model.TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    String groupID = Optional.ofNullable(fileLayoutInfo.getOrganization())
      .orElseThrow(() -> new CannotScanException("Group ID not provided."));
    String artifactID = Optional.ofNullable(fileLayoutInfo.getModule())
      .orElseThrow(() -> new CannotScanException("Artifact ID not provided."));
    String artifactVersion = Optional.ofNullable(fileLayoutInfo.getBaseRevision())
      .orElseThrow(() -> new CannotScanException("Artifact Version not provided."));

    SnykResult<io.snyk.sdk.model.TestResult> result;
    try {
      LOG.debug("Running Snyk test: {}", repoPath);
      result = snykClient.get(TestResult.class, request ->
        request
          .withPath(String.format("test/maven/%s/%s/%s",
            URLEncoder.encode(groupID, UTF_8),
            URLEncoder.encode(artifactID, UTF_8),
            URLEncoder.encode(artifactVersion, UTF_8)
          ))
          .withQueryParam("org", configurationModule.getProperty(API_ORGANIZATION))
          .withQueryParam("repository", Optional.empty())
      );
    } catch (Exception e) {
      throw new SnykAPIFailureException(e);
    }

    io.snyk.sdk.model.TestResult testResult = result.get().orElseThrow(() -> new SnykAPIFailureException(result));
    testResult.packageDetailsURL = getArtifactDetailsURL(groupID, artifactID, artifactVersion);
    return TestResultConverter.convert(testResult);
  }
}
