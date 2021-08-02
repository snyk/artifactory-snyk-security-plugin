package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
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

  public Optional<TestResult> scan(FileLayoutInfo fileLayoutInfo) {
    try {
      var result = snykClient.testMaven(
        Optional.ofNullable(fileLayoutInfo.getOrganization()).orElseThrow(() -> new RuntimeException("Group ID not provided.")),
        Optional.ofNullable(fileLayoutInfo.getModule()).orElseThrow(() -> new RuntimeException("Artifact ID not provided.")),
        Optional.ofNullable(fileLayoutInfo.getBaseRevision()).orElseThrow(() -> new RuntimeException("Artifact Version not provided.")),
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION)),
        Optional.empty()
      );
      if (result.isSuccessful()) {
        LOG.debug("testMaven response: {}", result.responseAsText.get());
        return result.get();
      }
    } catch (Exception ex) {
      LOG.error("Could not test maven artifact: {}", fileLayoutInfo, ex);
    }
    return Optional.empty();
  }
}
