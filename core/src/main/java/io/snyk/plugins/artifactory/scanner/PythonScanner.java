package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.api.v1.NewSnykClient;
import io.snyk.sdk.api.v1.SnykResult;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.slf4j.Logger;

import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.slf4j.LoggerFactory.getLogger;

class PythonScanner implements PackageScanner {

  private static final Logger LOG = getLogger(PythonScanner.class);

  private final ConfigurationModule configurationModule;
  private final NewSnykClient snykClient;

  PythonScanner(ConfigurationModule configurationModule, NewSnykClient snykClient) {
    this.configurationModule = configurationModule;
    this.snykClient = snykClient;
  }

  public Optional<TestResult> scan(FileLayoutInfo fileLayoutInfo) {
    String organization = configurationModule.getProperty(API_ORGANIZATION);
    try {
      SnykResult<TestResult> result = snykClient.testPip(fileLayoutInfo.getModule(),
        fileLayoutInfo.getBaseRevision(),
        Optional.of(organization));
      if (result.isSuccessful()) {
        LOG.debug("testPip response: {}", result.responseAsText.get());
        return result.get();
      }
    } catch (Exception ex) {
      LOG.error("Could not test python artifact: {}", fileLayoutInfo, ex);
    }
    return Optional.empty();
  }
}
