package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.slf4j.LoggerFactory.getLogger;

class MavenScanner implements PackageScanner {

  private static final Logger LOG = getLogger(MavenScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykClient snykClient;

  MavenScanner(ConfigurationModule configurationModule, SnykClient snykClient) {
    this.configurationModule = configurationModule;
    this.snykClient = snykClient;
  }

  private String getPackageDetailsURL(String groupID, String artifactID, String artifactVersion) {
    return "https://snyk.io/vuln/" + "maven:" + groupID + "%3A" + artifactID + "@" + artifactVersion;
  }

  public Optional<TestResult> scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    if (!fileLayoutInfo.isValid()) {
      LOG.warn("Artifact '{}' file layout info is not valid.", repoPath);
    }

    String groupID = Optional.ofNullable(fileLayoutInfo.getOrganization())
      .orElseThrow(() -> new CannotScanException("Group ID not provided."));
    String artifactID = Optional.ofNullable(fileLayoutInfo.getModule())
      .orElseThrow(() -> new CannotScanException("Artifact ID not provided."));
    String artifactVersion = Optional.ofNullable(fileLayoutInfo.getBaseRevision())
      .orElseThrow(() -> new CannotScanException("Artifact Version not provided."));

    try {
      var result = snykClient.testMaven(
        groupID,
        artifactID,
        artifactVersion,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION)),
        Optional.empty()
      );
      if (result.isSuccessful()) {
        LOG.debug("testMaven response: {}", result.responseAsText.get());
        var testResult = result.get();
        testResult.ifPresent(testResultSnykResult -> {
          testResultSnykResult.packageDetailsURL = getPackageDetailsURL(groupID, artifactID, artifactVersion);
        });
        return testResult;
      }
    } catch (Exception ex) {
      LOG.error("Could not test maven artifact: {}", fileLayoutInfo, ex);
    }
    return Optional.empty();
  }
}
