package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.slf4j.Logger;

import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.slf4j.LoggerFactory.getLogger;

class NpmScanner implements PackageScanner {

  private static final Logger LOG = getLogger(NpmScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykClient snykClient;

  NpmScanner(ConfigurationModule configurationModule, SnykClient snykClient) {
    this.configurationModule = configurationModule;
    this.snykClient = snykClient;
  }

  public Optional<TestResult> scan(FileLayoutInfo fileLayoutInfo) {
    String organization = configurationModule.getProperty(API_ORGANIZATION);
    try {
      var result = snykClient.testNpm(fileLayoutInfo.getModule(),
        fileLayoutInfo.getBaseRevision(),
        Optional.of(organization));
      if (result.isSuccessful()) {
        LOG.debug("testNpm response: {}", result.responseAsText.get());
        return result.get();
      }
    } catch (Exception ex) {
      LOG.error("Could not test npm artifact: {}", fileLayoutInfo, ex);
    }
    return Optional.empty();
  }
}
