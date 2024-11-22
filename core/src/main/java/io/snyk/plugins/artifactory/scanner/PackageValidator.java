package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.ValidationSettings;
import io.snyk.sdk.model.Severity;
import org.artifactory.exception.CancelException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

import static java.lang.String.format;

public class PackageValidator {

  private static final Logger LOG = LoggerFactory.getLogger(PackageValidator.class);

  private final ValidationSettings settings;

  public PackageValidator(ValidationSettings settings) {
    this.settings = settings;
  }

  public void validate(MonitoredArtifact artifact) {
    validateVulnerabilityIssues(artifact);
    validateLicenseIssues(artifact);
  }

  private void validateVulnerabilityIssues(MonitoredArtifact artifact) {
    validateIssues(
      artifact.getTestResult().getVulnSummary(),
      settings.getVulnSeverityThreshold(),
      artifact.getIgnores().shouldIgnoreVulnIssues(),
      "vulnerabilities",
      artifact
    );
  }

  private void validateLicenseIssues(MonitoredArtifact artifact) {
    validateIssues(
      artifact.getTestResult().getLicenseSummary(),
      settings.getLicenseSeverityThreshold(),
      artifact.getIgnores().shouldIgnoreLicenseIssues(),
      "license issues",
      artifact
    );
  }

  private void validateIssues(IssueSummary summary, Optional<Severity> threshold, boolean ignoreIssues, String issueType, MonitoredArtifact artifact) {
    if(threshold.isEmpty()) {
      LOG.debug("No severity threshold set for {}", issueType);
      return;
    }

    int countAboveThreshold = summary.getCountAtOrAbove(threshold.get());
    if (countAboveThreshold == 0) {
      LOG.debug("No {} with severity {} or higher: {}", issueType, threshold, artifact.getPath());
      return;
    }

    if (ignoreIssues) {
      LOG.debug("Allowing download because {} are ignored: {}", issueType, artifact.getPath());
      return;
    }

    LOG.debug("Package has {} with severity {} or higher: {}", issueType, threshold, artifact.getPath());
    throw new CancelException(format("Artifact has %s with %s severity or higher: %s. Details: %s",
      issueType, threshold.get(), artifact.getPath(), artifact.getTestResult().getDetailsUrl()
    ), 403);
  }

}
