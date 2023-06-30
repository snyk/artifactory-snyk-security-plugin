package io.snyk.sdk.model.v3;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.v1.Issue;
import io.snyk.sdk.model.v1.Issues;
import io.snyk.sdk.model.v1.TestResult;
import io.snyk.sdk.model.v1.Vulnerability;

import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;

public class IssuesResult implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty("data")
  private List<IssuesData> data;

  // Remap the JSON API response to a TestResult in order to avoid too much
  // custom code in the vulnerability detection logic of the Artifactory Plugin.
  // We do not care about many details about this, only if there are issues, and what
  // the severity is, in order to block downloads.
  public TestResult toTestResult() {
    TestResult testResult = new TestResult();
    testResult.issues = new Issues();

    // Map the JsonApis vulnerability attributes
    List<Vulnerability> vulnerabilities = data.stream()
      .filter(issuesData -> issuesData.type == IssueType.ISSUE)
      .map(issuesData -> {
        Vulnerability vulnerability = new Vulnerability();

        // The Snyk plugin only scans for severity, the rest is ignored
        vulnerability.severity = issuesData.attributes.effectiveSeverityLevel;
        return vulnerability;
      })
      .collect(Collectors.toList());

    testResult.issues.vulnerabilities = vulnerabilities;

    // Map the JsonApis license attributes
    List<Issue> licenses = data.stream()
      .filter(issuesData -> issuesData.type == IssueType.LICENSE)
      .map(issuesData -> {
        Issue licenseIssue = new Issue();

        // The Snyk plugin only scans for severity, the rest is ignored
        licenseIssue.severity = issuesData.attributes.effectiveSeverityLevel;
        return licenseIssue;
      })
      .collect(Collectors.toList());

    testResult.issues.licenses = licenses;

    return testResult;
  }
}

class IssuesData implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty("type")
  public IssueType type;
  @JsonProperty("attributes")
  public IssuesAttributes attributes;
}

class IssuesAttributes implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty("effective_severity_level")
  public Severity effectiveSeverityLevel;
}

