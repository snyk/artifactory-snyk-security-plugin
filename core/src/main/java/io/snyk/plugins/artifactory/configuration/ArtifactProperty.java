package io.snyk.plugins.artifactory.configuration;

public enum ArtifactProperty {
  ISSUE_URL("snyk.issue.url"),
  ISSUE_VULNERABILITIES("snyk.issue.vulnerabilities"),
  ISSUE_VULNERABILITIES_FORCE_DOWNLOAD("snyk.issue.vulnerabilities.forceDownload"),
  ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO("snyk.issue.vulnerabilities.forceDownload.info"),
  ISSUE_LICENSES("snyk.issue.licenses"),
  ISSUE_LICENSES_FORCE_DOWNLOAD("snyk.issue.licenses.forceDownload"),
  ISSUE_LICENSES_FORCE_DOWNLOAD_INFO("snyk.issue.licenses.forceDownload.info");

  private final String propertyKey;

  ArtifactProperty(String propertyKey) {
    this.propertyKey = propertyKey;
  }

  public String getPropertyKey() {
    return propertyKey;
  }
}
