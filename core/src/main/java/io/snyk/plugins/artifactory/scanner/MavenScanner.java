package io.snyk.plugins.artifactory.scanner;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.slf4j.Logger;
import retrofit2.Response;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.slf4j.LoggerFactory.getLogger;

class MavenScanner {

  private static final Logger LOG = getLogger(MavenScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykClient snykClient;

  MavenScanner(ConfigurationModule configurationModule, SnykClient snykClient) {
    this.configurationModule = configurationModule;
    this.snykClient = snykClient;
  }

  public TestResult scan(FileLayoutInfo fileLayoutInfo) {
    String organization = configurationModule.getProperty(API_ORGANIZATION);

    TestResult testResult = null;
    try {
      Response<TestResult> response = snykClient.testMaven(fileLayoutInfo.getOrganization(),
                                                           fileLayoutInfo.getModule(),
                                                           fileLayoutInfo.getBaseRevision(),
                                                           organization,
                                                           null).execute();
      if (response.isSuccessful() && response.body() != null) {
        testResult = response.body();
        String responseAsText = new ObjectMapper().writeValueAsString(response.body());
        LOG.debug("testMaven response: {}", responseAsText);
      }
    } catch (IOException ex) {
      LOG.error("Could not test maven artifact: {}", fileLayoutInfo, ex);
    }

    return testResult;
  }
}
