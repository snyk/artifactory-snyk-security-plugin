package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;

import java.util.Objects;
import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.ISSUE_LICENSES_FORCE_DOWNLOAD;
import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.ISSUE_VULNERABILITIES_FORCE_DOWNLOAD;

public class Ignores {

  private final boolean ignoreVulnIssues;

  private final boolean ignoreLicenseIssues;

  public Ignores() {
    this(false, false);
  }

  private Ignores(boolean ignoreVulnIssues, boolean ignoreLicenseIssues) {
    this.ignoreVulnIssues = ignoreVulnIssues;
    this.ignoreLicenseIssues = ignoreLicenseIssues;
  }

  public boolean shouldIgnoreVulnIssues() {
    return ignoreVulnIssues;
  }

  public Ignores withIgnoreVulnIssues(boolean ignoreVulnIssues) {
    return new Ignores(ignoreVulnIssues, ignoreLicenseIssues);
  }

  public boolean shouldIgnoreLicenseIssues() {
    return ignoreLicenseIssues;
  }

  public Ignores withIgnoreLicenseIssues(boolean ignoreLicenseIssues) {
    return new Ignores(ignoreVulnIssues, ignoreLicenseIssues);
  }

  public static Ignores read(ArtifactProperties properties) {
    boolean ignoreVulnIssues = properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD).equals(Optional.of("true"));
    boolean ignoreLicenseIssues = properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD).equals(Optional.of("true"));
    return new Ignores(ignoreVulnIssues, ignoreLicenseIssues);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Ignores ignores = (Ignores) o;
    return ignoreVulnIssues == ignores.ignoreVulnIssues && ignoreLicenseIssues == ignores.ignoreLicenseIssues;
  }

  @Override
  public int hashCode() {
    return Objects.hash(ignoreVulnIssues, ignoreLicenseIssues);
  }

  @Override
  public String toString() {
    return "Ignores{" +
        "ignoreVulnIssues=" + ignoreVulnIssues +
        ", ignoreLicenseIssues=" + ignoreLicenseIssues +
        '}';
  }
}
