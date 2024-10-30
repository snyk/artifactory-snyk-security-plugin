package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.ArtifactProperty;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;

import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_LICENSES_FORCE_DOWNLOAD;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_VULNERABILITIES_FORCE_DOWNLOAD;

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

  public static Ignores fromProperties(Repositories repositories, RepoPath repoPath) {
    boolean ignoreVulnIssues = readIgnoreFlag(repositories, repoPath, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD);
    boolean ignoreLicenseIssues = readIgnoreFlag(repositories, repoPath, ISSUE_LICENSES_FORCE_DOWNLOAD);
    return new Ignores(ignoreVulnIssues, ignoreLicenseIssues);
  }

  private static boolean readIgnoreFlag(Repositories repositories, RepoPath repoPath, ArtifactProperty property) {
    final String vulnerabilitiesForceDownloadProperty = property.propertyKey();
    final String vulnerabilitiesForceDownload = repositories.getProperty(repoPath, vulnerabilitiesForceDownloadProperty);
    return "true".equalsIgnoreCase(vulnerabilitiesForceDownload);
  }
}
