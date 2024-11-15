package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.model.Severity;

import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_LICENSE_THRESHOLD;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD;

public class ValidationSettings {

  private final Optional<Severity> vulnSeverityThreshold;

  private final Optional<Severity> licenseSeverityThreshold;

  public ValidationSettings() {
    this(Optional.of(Severity.HIGH), Optional.of(Severity.HIGH));
  }

  private ValidationSettings(Optional<Severity> vulnSeverityThreshold, Optional<Severity> licenseSeverityThreshold) {
    this.vulnSeverityThreshold = vulnSeverityThreshold;
    this.licenseSeverityThreshold = licenseSeverityThreshold;
  }

  public ValidationSettings withVulnSeverityThreshold(Optional<Severity> threshold) {
    return new ValidationSettings(threshold, licenseSeverityThreshold);
  }

  public ValidationSettings withLicenseSeverityThreshold(Optional<Severity> threshold) {
    return new ValidationSettings(vulnSeverityThreshold, threshold);
  }

  public Optional<Severity> getVulnSeverityThreshold() {
    return vulnSeverityThreshold;
  }

  public Optional<Severity> getLicenseSeverityThreshold() {
    return licenseSeverityThreshold;
  }

  public static ValidationSettings from(ConfigurationModule config) {
    return from(
      config.getPropertyOrDefault(SCANNER_VULNERABILITY_THRESHOLD),
      config.getPropertyOrDefault(SCANNER_LICENSE_THRESHOLD)
    );
  }

  public static ValidationSettings from(String vulnThreshold, String licenseThreshold) {
    return new ValidationSettings(
      parseSeverity(vulnThreshold),
      parseSeverity(licenseThreshold)
    );
  }

  private static Optional<Severity> parseSeverity(String severityStr) {
    if ("none".equalsIgnoreCase(severityStr)) {
      return Optional.empty();
    }
    Severity severity = Severity.of(severityStr);
    if (severity == null) {
      throw new IllegalArgumentException("Invalid severity threshold: " + severityStr);
    }
    return Optional.of(severity);
  }
}
