package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.model.*;
import io.snyk.sdk.model.Severity;
import org.artifactory.exception.CancelException;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

class PackageValidatorTest {

  @Test
  void validate_severityBelowThreshold_allowed() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Optional.of(Severity.MEDIUM))
      .withLicenseSeverityThreshold(Optional.of(Severity.CRITICAL));
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.LOW)),
        IssueSummary.from(Stream.of(Severity.MEDIUM)),
        URI.create("https://snyk.io/package/version")
      ),
      new Ignores()
    );

    assertThatCode(() -> validator.validate(artifact)).doesNotThrowAnyException();
  }

  @Test
  void validate_vulnIssueAboveThreshold_forbidden() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Optional.of(Severity.HIGH))
      .withLicenseSeverityThreshold(Optional.of(Severity.LOW));
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.HIGH)),
        IssueSummary.from(Stream.empty()),
        URI.create("https://snyk.io/package/version")
      ),
      new Ignores()
    );

    assertThatThrownBy(() -> validator.validate(artifact)).isExactlyInstanceOf(CancelException.class);
  }

  @Test
  void validate_vulnIssuesIgnored_allowed() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Optional.of(Severity.HIGH))
      .withLicenseSeverityThreshold(Optional.of(Severity.LOW));
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.HIGH)),
        IssueSummary.from(Stream.empty()),
        URI.create("https://snyk.io/package/version")
      ),
      new Ignores().withIgnoreVulnIssues(true)
    );

    assertThatCode(() -> validator.validate(artifact)).doesNotThrowAnyException();
  }

  @Test
  void validate_licenseIssueAboveThreshold_forbidden() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Optional.of(Severity.LOW))
      .withLicenseSeverityThreshold(Optional.of(Severity.MEDIUM));
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      new TestResult(
        IssueSummary.from(Stream.empty()),
        IssueSummary.from(Stream.of(Severity.MEDIUM)),
        URI.create("https://snyk.io/package/version")
      ),
      new Ignores()
    );

    assertThatThrownBy(() -> validator.validate(artifact)).isExactlyInstanceOf(CancelException.class);
  }


  @Test
  void validate_thresholdNone_allowed() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Optional.empty())
      .withLicenseSeverityThreshold(Optional.empty());
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.CRITICAL)),
        IssueSummary.from(Stream.of(Severity.CRITICAL)),
        URI.create("https://snyk.io/package/version")
      ),
      new Ignores()
    );

    assertThatCode(() -> validator.validate(artifact)).doesNotThrowAnyException();
  }

  @Test
  void validate_licenseIssuesIgnored_allowed() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Optional.of(Severity.LOW))
      .withLicenseSeverityThreshold(Optional.of(Severity.MEDIUM));
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      new TestResult(
        IssueSummary.from(Stream.empty()),
        IssueSummary.from(Stream.of(Severity.MEDIUM)),
        URI.create("https://snyk.io/package/version")
      ),
      new Ignores().withIgnoreLicenseIssues(true)
    );

    assertThatCode(() -> validator.validate(artifact)).doesNotThrowAnyException();
  }

  @Test
  void validate_includesSnykDetailsUrlInCancelException() {
    ValidationSettings settings = new ValidationSettings()
      .withVulnSeverityThreshold(Optional.of(Severity.LOW));
    PackageValidator validator = new PackageValidator(settings);
    MonitoredArtifact artifact = new MonitoredArtifact("",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.LOW)),
        IssueSummary.from(Stream.empty()),
        URI.create("https://snyk.io/package/details")
      ),
      new Ignores()
    );

    assertThatThrownBy(() -> validator.validate(artifact))
      .isExactlyInstanceOf(CancelException.class)
      .hasMessageContaining("https://snyk.io/package/details");
  }

  @Test
  void validate_includesCreatedDateDelay() {
    Integer createdDelayDays = 14;
    ValidationSettings settings = new ValidationSettings()
    .withCreatedDelayDays(Optional.of(createdDelayDays))
    .withVulnSeverityThreshold(Optional.empty())
    .withLicenseSeverityThreshold(Optional.empty());

    PackageValidator validator = new PackageValidator(settings);
    
    MonitoredArtifact artifact = new MonitoredArtifact("",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.LOW)),
        IssueSummary.from(Stream.empty()),
        URI.create("https://snyk.io/package/details")
      ),
      new Ignores(),
      Instant.now()
    );

    assertThatThrownBy(() -> validator.validate(artifact))
    .isExactlyInstanceOf(CancelException.class)
    .hasMessageContaining("Artifact was created 0 days ago, which is less than the configured delay of 14 days");
  }
}
