package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;

import java.net.URI;
import java.time.ZonedDateTime;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.*;

public class TestResult {
  private final ZonedDateTime timestamp;
  private final IssueSummary vulnSummary;
  private final IssueSummary licenseSummary;
  private final URI detailsUrl;

  public TestResult(IssueSummary vulnSummary, IssueSummary licenseSummary, URI detailsUrl) {
    this.timestamp = ZonedDateTime.now();
    this.vulnSummary = vulnSummary;
    this.licenseSummary = licenseSummary;
    this.detailsUrl = detailsUrl;
  }

  public IssueSummary getVulnSummary() {
    return vulnSummary;
  }

  public IssueSummary getLicenseSummary() {
    return licenseSummary;
  }

  public URI getDetailsUrl() {
    return detailsUrl;
  }

  public ZonedDateTime getTimestamp() {
    return timestamp;
  }

  public void write(ArtifactProperties properties) {
    properties.setProperty(ISSUE_VULNERABILITIES, getVulnSummary().toString());
    properties.setProperty(ISSUE_LICENSES, getLicenseSummary().toString());
    properties.setProperty(ISSUE_URL, getDetailsUrl().toString());
  }
}
