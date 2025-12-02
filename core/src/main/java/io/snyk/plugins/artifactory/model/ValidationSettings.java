package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.model.Severity;

import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_CREATED_DELAY_DAYS;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_LICENSE_THRESHOLD;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD;

public class ValidationSettings {

  private final Optional<Severity> vulnSeverityThreshold;
  private final Optional<Severity> licenseSeverityThreshold;
  private final Optional<Integer> createdDelayDays;

  public ValidationSettings() {
    this(Optional.of(Severity.HIGH), Optional.of(Severity.HIGH), Optional.of(0));
  }

  private ValidationSettings(Optional<Severity> vulnSeverityThreshold, Optional<Severity> licenseSeverityThreshold, Optional<Integer> createdDelayDays) {
    this.vulnSeverityThreshold = vulnSeverityThreshold;
    this.licenseSeverityThreshold = licenseSeverityThreshold;
    this.createdDelayDays = createdDelayDays;
  }

  public ValidationSettings withVulnSeverityThreshold(Optional<Severity> threshold) {
    return new ValidationSettings(threshold, licenseSeverityThreshold, createdDelayDays);
  }

  public ValidationSettings withLicenseSeverityThreshold(Optional<Severity> threshold) {
    return new ValidationSettings(vulnSeverityThreshold, threshold, createdDelayDays);
  }

  public ValidationSettings withCreatedDelayDays(Optional<Integer> days) {
    return new ValidationSettings(vulnSeverityThreshold, licenseSeverityThreshold, days);
  }

  public Optional<Severity> getVulnSeverityThreshold() {
    return vulnSeverityThreshold;
  }

  public Optional<Severity> getLicenseSeverityThreshold() {
    return licenseSeverityThreshold;
  }

  public Optional<Integer> getCreatedDelayDays() {
    return createdDelayDays;
  }

  public static ValidationSettings from(ConfigurationModule config) {
    return from(
      config.getPropertyOrDefault(SCANNER_VULNERABILITY_THRESHOLD),
      config.getPropertyOrDefault(SCANNER_LICENSE_THRESHOLD),
      config.getPropertyOrDefault(SCANNER_CREATED_DELAY_DAYS)
    );
  }

  public static ValidationSettings from(String vulnThreshold, String licenseThreshold) {
    return from(vulnThreshold, licenseThreshold, "0");
  }

  public static ValidationSettings from(String vulnThreshold, String licenseThreshold, String createdDelayDaysStr) {
    return new ValidationSettings(
      parseSeverity(vulnThreshold),
      parseSeverity(licenseThreshold),
      Optional.of(Integer.parseInt(createdDelayDaysStr))
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
