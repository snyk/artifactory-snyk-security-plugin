package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.sdk.model.purl.PurlIssues;

import java.net.URI;
import java.util.stream.Stream;

public class TestResultConverter {

  public static TestResult convert(io.snyk.sdk.model.TestResult result) {
    return new TestResult(
      IssueSummary.from(result.issues.vulnerabilities),
      IssueSummary.from(result.issues.licenses),
      URI.create(result.packageDetailsURL)
    );
  }

  public static TestResult convert(PurlIssues issues) {
    return new TestResult(
      IssueSummary.fromPurlIssues(issues.purlIssues),
      IssueSummary.from(Stream.empty()),
      URI.create(issues.packageDetailsUrl)
    );
  }
}
