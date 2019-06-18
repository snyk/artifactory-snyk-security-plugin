package io.snyk.plugins.artifactory.core.scanner;

import java.io.IOException;
import java.util.Properties;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.slf4j.Logger;
import retrofit2.Response;

import static org.slf4j.LoggerFactory.getLogger;

public class MavenScanner implements Scanner {
  private static final Logger LOG = getLogger(MavenScanner.class);

  private final Properties properties;
  private final SnykClient snykClient;

  public MavenScanner(Properties properties, SnykClient snykClient) {
    this.properties = properties;
    this.snykClient = snykClient;
  }

  @Override
  public TestResult scan(FileLayoutInfo fileLayoutInfo) {
    String organisation = properties.getProperty("snyk.api.organisation");

    TestResult testResult = null;
    try {
      Response<TestResult> response = snykClient.testMaven(fileLayoutInfo.getOrganization(),
                                                           fileLayoutInfo.getModule(),
                                                           fileLayoutInfo.getBaseRevision(),
                                                           organisation,
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
