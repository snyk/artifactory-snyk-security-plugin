package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.ValidationSettings;
import io.snyk.sdk.model.Severity;
import org.artifactory.exception.CancelException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
      artifact.getVulnSummary(),
      settings.getVulnSeverityThreshold(),
      artifact.getIgnores().shouldIgnoreVulnIssues(),
      format("VULNERABILITIES, %s", artifact.getPath())
    );
  }

  private void validateLicenseIssues(MonitoredArtifact artifact) {
    validateIssues(
      artifact.getLicenseSummary(),
      settings.getLicenseSeverityThreshold(),
      artifact.getIgnores().shouldIgnoreLicenseIssues(),
      format("LICENSES, %s", artifact.getPath())
    );
  }

  private void validateIssues(IssueSummary summary, Severity threshold, boolean ignoreIssues, String logContext) {
    int countAboveThreshold = summary.getCountAtOrAbove(threshold);
    if (countAboveThreshold == 0) {
      LOG.debug("No issues with severity {} or higher: {}", threshold, logContext);
      return;
    }

    if (ignoreIssues) {
      LOG.debug("Allowing download because issues are ignored: {}", logContext);
      return;
    }

    LOG.debug("Package has issues with severity {} or higher: {}", threshold, logContext);
    throw new CancelException(format("Artifact has license issues with severity %s or higher: %s", threshold, logContext), 403);
  }

}
