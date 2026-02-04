package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.ValidationSettings;
import io.snyk.sdk.model.Severity;
import org.artifactory.exception.CancelException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static java.lang.String.format;

public class PackageValidator {

  private static final Logger LOG = LoggerFactory.getLogger(PackageValidator.class);

  private final ValidationSettings settings;

  public PackageValidator(ValidationSettings settings) {
    this.settings = settings;
  }

  public void validate(MonitoredArtifact artifact) {
    validateLastModifiedDelay(artifact);
    validateVulnerabilityIssues(artifact);
    validateLicenseIssues(artifact);
  }

  private void validateLastModifiedDelay(MonitoredArtifact artifact) {
    Integer delayDays = settings.getLastModifiedDelayDays().get();
    if (delayDays == null || delayDays <= 0) {
      LOG.debug("Last modifed date delay is disabled ({} days)", delayDays);
      return;
    }

    Optional<Instant> lastModifiedDate = artifact.getLastModifiedDate();
    if (lastModifiedDate.isEmpty()) {
      LOG.debug("Last modified date not available for {}, skipping created delay check", artifact.getPath());
      return;
    }

    Instant now = Instant.now();
    long daysSinceLastModified = ChronoUnit.DAYS.between(lastModifiedDate.get(), now);
    
    if (daysSinceLastModified < delayDays) {
      LOG.debug("Package created {} days ago, which is less than the delay of {} days: {}", 
                daysSinceLastModified, delayDays, artifact.getPath());
      throw new CancelException(format(
        "Artifact was created %d days ago, which is less than the configured delay of %d days: %s",
        daysSinceLastModified, delayDays, artifact.getPath()
      ), 403);
    }

    LOG.debug("Package created {} days ago, which exceeds the delay of {} days: {}", 
              daysSinceLastModified, delayDays, artifact.getPath());
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
