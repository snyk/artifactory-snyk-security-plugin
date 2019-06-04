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

public class NpmScanner {
  private static final Logger LOG = getLogger(NpmScanner.class);

  private final Properties properties;
  private final SnykClient snykClient;

  public NpmScanner(Properties properties, SnykClient snykClient) {
    this.properties = properties;
    this.snykClient = snykClient;
  }

  public TestResult performScan(FileLayoutInfo fileLayoutInfo) {
    String organisation = properties.getProperty("snyk.api.organisation");

    TestResult testResult = null;
    try {
      Response<TestResult> response = snykClient.testNpm(fileLayoutInfo.getModule(),
                                                         fileLayoutInfo.getBaseRevision(),
                                                         organisation).execute();
      if (response.isSuccessful() && response.body() != null) {
        testResult = response.body();
        String responseAsText = new ObjectMapper().writeValueAsString(response.body());
        LOG.debug("testNpm response: {}", responseAsText);
      }
    } catch (IOException ex) {
      LOG.error("Could not test npm artifact: {}", fileLayoutInfo, ex);
    }
    return testResult;
  }
}
