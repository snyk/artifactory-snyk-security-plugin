package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.TestResult;

import java.net.URI;

public class TestResultConverter {

  public static TestResult convert(io.snyk.sdk.model.TestResult result) {
    return new TestResult(
      IssueSummary.from(result.issues.vulnerabilities),
      IssueSummary.from(result.issues.licenses),
      URI.create(result.packageDetailsURL)
    );
  }
}
