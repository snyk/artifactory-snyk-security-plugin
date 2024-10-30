package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.model.Ignores;
import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.ValidationSettings;
import io.snyk.sdk.model.Severity;
import org.artifactory.exception.CancelException;
import org.junit.jupiter.api.Test;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PackageValidatorTest {

  @Test
  void validate_severityBelowThreshold_allowed() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Severity.MEDIUM)
      .withLicenseSeverityThreshold(Severity.CRITICAL);
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      IssueSummary.from(Stream.of(Severity.LOW)),
      IssueSummary.from(Stream.of(Severity.MEDIUM)),
      new Ignores()
    );

    assertDoesNotThrow(() -> validator.validate(artifact));
  }

  @Test
  void validate_vulnIssueAboveThreshold_forbidden() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Severity.HIGH)
      .withLicenseSeverityThreshold(Severity.LOW);
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      IssueSummary.from(Stream.of(Severity.HIGH)),
      IssueSummary.from(Stream.empty()),
      new Ignores()
    );

    assertThrows(CancelException.class, () -> validator.validate(artifact));
  }

  @Test
  void validate_vulnIssuesIgnored_allowed() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Severity.HIGH)
      .withLicenseSeverityThreshold(Severity.LOW);
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      IssueSummary.from(Stream.of(Severity.HIGH)),
      IssueSummary.from(Stream.empty()),
      new Ignores().withIgnoreVulnIssues(true)
    );

    assertDoesNotThrow(() -> validator.validate(artifact));
  }

  @Test
  void validate_licenseIssueAboveThreshold_forbidden() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Severity.LOW)
      .withLicenseSeverityThreshold(Severity.MEDIUM);
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      IssueSummary.from(Stream.empty()),
      IssueSummary.from(Stream.of(Severity.MEDIUM)),
      new Ignores()
    );

    assertThrows(CancelException.class, () -> validator.validate(artifact));
  }

  @Test
  void validate_licenseIssuesIgnored_allowed() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Severity.LOW)
      .withLicenseSeverityThreshold(Severity.MEDIUM);
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      IssueSummary.from(Stream.empty()),
      IssueSummary.from(Stream.of(Severity.MEDIUM)),
      new Ignores().withIgnoreLicenseIssues(true)
    );

    assertDoesNotThrow(() -> validator.validate(artifact));
  }
}
