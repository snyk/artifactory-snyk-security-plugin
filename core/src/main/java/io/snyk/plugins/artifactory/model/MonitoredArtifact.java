package io.snyk.plugins.artifactory.model;

public class MonitoredArtifact {

  private final String path;
  private final IssueSummary vulnSummary;
  private final IssueSummary licenseSummary;
  private final Ignores ignores;

  public MonitoredArtifact(String path, IssueSummary vulnSummary, IssueSummary licenseSummary, Ignores ignores) {
    this.path = path;
    this.vulnSummary = vulnSummary;
    this.licenseSummary = licenseSummary;
    this.ignores = ignores;
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
}
