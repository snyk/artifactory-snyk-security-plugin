package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.model.Severity;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_LICENSE_THRESHOLD;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD;

public class ValidationSettings {

  private final Severity vulnSeverityThreshold;

  private final Severity licenseSeverityThreshold;

  public ValidationSettings() {
    this(Severity.HIGH, Severity.HIGH);
  }

  private ValidationSettings(Severity vulnSeverityThreshold, Severity licenseSeverityThreshold) {
    this.vulnSeverityThreshold = vulnSeverityThreshold;
    this.licenseSeverityThreshold = licenseSeverityThreshold;
  }

  public ValidationSettings withVulnSeverityThreshold(Severity threshold) {
    return new ValidationSettings(threshold, licenseSeverityThreshold);
  }

  public ValidationSettings withLicenseSeverityThreshold(Severity threshold) {
    return new ValidationSettings(vulnSeverityThreshold, threshold);
  }

  public Severity getVulnSeverityThreshold() {
    return vulnSeverityThreshold;
  }

  public Severity getLicenseSeverityThreshold() {
    return licenseSeverityThreshold;
  }

  public static ValidationSettings from(ConfigurationModule config) {
    return new ValidationSettings()
      .withVulnSeverityThreshold(Severity.of(config.getPropertyOrDefault(SCANNER_VULNERABILITY_THRESHOLD)))
      .withLicenseSeverityThreshold(Severity.of(config.getPropertyOrDefault(SCANNER_LICENSE_THRESHOLD)));
  }
}
