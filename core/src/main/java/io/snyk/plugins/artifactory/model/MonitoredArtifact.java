package io.snyk.plugins.artifactory.model;

import java.net.URI;

public class MonitoredArtifact {

  private final String path;
  private final IssueSummary vulnSummary;
  private final IssueSummary licenseSummary;
  private final Ignores ignores;
  private final URI detailsUrl;

  public MonitoredArtifact(String path, IssueSummary vulnSummary, IssueSummary licenseSummary, Ignores ignores, URI detailsUrl) {
    this.path = path;
    this.vulnSummary = vulnSummary;
    this.licenseSummary = licenseSummary;
    this.ignores = ignores;
    this.detailsUrl = detailsUrl;
  }

  public String getPath() {
    return path;
  }

  public IssueSummary getVulnSummary() {
    return vulnSummary;
  }

  public IssueSummary getLicenseSummary() {
    return licenseSummary;
  }

  public Ignores getIgnores() {
    return ignores;
  }

  public URI getDetailsUrl() {
    return detailsUrl;
  }
}
