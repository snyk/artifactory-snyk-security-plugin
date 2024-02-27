package io.snyk.sdk.model.v1;

import java.io.Serializable;
import java.util.function.Predicate;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.snyk.sdk.model.Organisation;
import io.snyk.sdk.model.ScanResponse;
import io.snyk.sdk.model.Severity;

import static io.snyk.sdk.util.Predicates.distinctByKey;

/**
 * The test result is the object returned from the API giving the results of testing a package
 * for issues.
 */
public class TestResult implements Serializable, ScanResponse {

  private static final long serialVersionUID = 1L;

  @JsonProperty("ok")
  public boolean success;
  @JsonProperty("issues")
  public Issues issues;
  @JsonProperty("dependencyCount")
  public int dependencyCount;
  @JsonProperty("org")
  public Organisation organisation;
  @JsonProperty("packageManager")
  public String packageManager;
  private String packageDetailsUrl;

  public long getCountOfSecurityIssuesAtOrAboveSeverity(Severity s) {
    Predicate<Issue> isAtOrAboveSeverity = i -> i.severity.ordinal() >= s.ordinal();
    return issues.vulnerabilities.stream()
      .filter(isAtOrAboveSeverity)
      .count();
  }

  public long getCountOfSecurityIssuesAtSeverity(Severity s) {
    return issues.vulnerabilities.stream()
      .filter(issue -> issue.severity == s)
      .filter(distinctByKey(issue -> issue.id))
      .count();
  }

  public long getCountOfLicenseIssuesAtOrAboveSeverity(Severity s) {
    Predicate<Issue> isAtOrAboveSeverity = i -> i.severity.ordinal() >= s.ordinal();
    return issues.licenses.stream()
      .filter(isAtOrAboveSeverity)
      .count();
  }

  public long getCountOfLicenseIssuesAtSeverity(Severity s) {
    return issues.licenses.stream()
      .filter(issue -> issue.severity == s)
      .filter(distinctByKey(issue -> issue.id))
      .count();
  }

  public String getPackageDetailsUrl() {
    return packageDetailsUrl;
  }

  public void setPackageDetailsUrl(String packageDetailsUrl) {
    this.packageDetailsUrl = packageDetailsUrl;
  }
}
