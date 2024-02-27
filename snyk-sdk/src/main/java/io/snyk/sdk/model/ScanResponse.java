package io.snyk.sdk.model;

public interface ScanResponse {
  long getCountOfSecurityIssuesAtOrAboveSeverity(Severity s);
  long getCountOfSecurityIssuesAtSeverity(Severity s);
  long getCountOfLicenseIssuesAtOrAboveSeverity(Severity s);
  long getCountOfLicenseIssuesAtSeverity(Severity s);
  String getPackageDetailsUrl();
  void setPackageDetailsUrl(String packageDetailsUrl);
}
