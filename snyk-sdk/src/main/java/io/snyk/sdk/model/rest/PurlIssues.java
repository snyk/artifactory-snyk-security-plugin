package io.snyk.sdk.model.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.snyk.sdk.model.ScanResponse;
import io.snyk.sdk.model.Severity;

import java.io.Serializable;
import java.util.List;
import java.util.function.Predicate;

import static io.snyk.sdk.util.Predicates.distinctByKey;

public class PurlIssues implements Serializable, ScanResponse {

  private static final long serialVersionUID = 1L;

  @JsonProperty("data")
  public List<PurlIssue> purlIssues;
  private String packageDetailsUrl;

  public long getCountOfSecurityIssuesAtOrAboveSeverity(Severity s) {
    Predicate<PurlIssue> isAtOrAboveSeverity = i -> i.attribute.effective_severity_level.ordinal() >= s.ordinal();
    return purlIssues.stream()
      .filter(isAtOrAboveSeverity)
      .count();
    // .filter(issue -> issue.attribute.effective_severity_level == Severity.MEDIUM || issue.attribute.effective_severity_level == Severity.HIGH || issue.attribute.effective_severity_level == Severity.CRITICAL)
  }

  public long getCountOfSecurityIssuesAtSeverity(Severity s) {
    return purlIssues.stream()
      .filter(issue -> issue.attribute.effective_severity_level == s)
      .filter(distinctByKey(issue -> issue.attribute.key))
      .count();
  }

  // placeholder methods - list-purl-issues response does not return license information
  public long getCountOfLicenseIssuesAtOrAboveSeverity(Severity s) {
    return 0;
  }

  public long getCountOfLicenseIssuesAtSeverity(Severity s) {
    return 0;
  }

  public String getPackageDetailsUrl() {
    return packageDetailsUrl;
  }

  public void setPackageDetailsUrl(String packageDetailsUrl) {
    this.packageDetailsUrl = packageDetailsUrl;
  }
}
