package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.sdk.model.*;
import org.artifactory.exception.CancelException;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_LICENSES_FORCE_DOWNLOAD;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_VULNERABILITIES_FORCE_DOWNLOAD;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PackageValidatorTest {

  @Test
  void validate_severityBelowThreshold_allowed() {
    Repositories repositories = mock(Repositories.class);
    RepoPath repoPath = mock(RepoPath.class);

    ConfigurationModule configurationModule = pluginConfig(Severity.MEDIUM, Severity.CRITICAL);

    PackageValidator validator = new PackageValidator(configurationModule, repositories);
    TestResult testResult = getTestResult(List.of(Severity.LOW), List.of(Severity.MEDIUM));

    assertDoesNotThrow(() -> validator.validate(testResult, repoPath));
  }

  @Test
  void validate_vulnIssueAboveThreshold_forbidden() {
    Repositories repositories = mock(Repositories.class);
    RepoPath repoPath = mock(RepoPath.class);

    ConfigurationModule configurationModule = pluginConfig(Severity.HIGH, Severity.LOW);

    PackageValidator validator = new PackageValidator(configurationModule, repositories);
    TestResult testResult = getTestResult(List.of(Severity.HIGH), List.of());

    assertThrows(CancelException.class, () -> validator.validate(testResult, repoPath));
  }

  @Test
  void validate_vulnForceDownload_allowed() {
    Repositories repositories = mock(Repositories.class);
    RepoPath repoPath = mock(RepoPath.class);

    when(repositories.getProperty(repoPath, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD.propertyKey())).thenReturn("true");

    ConfigurationModule configurationModule = pluginConfig(Severity.HIGH, Severity.LOW);

    PackageValidator validator = new PackageValidator(configurationModule, repositories);
    TestResult testResult = getTestResult(List.of(Severity.HIGH), List.of());

    assertDoesNotThrow(() -> validator.validate(testResult, repoPath));
  }

  @Test
  void validate_licenseIssueAboveThreshold_forbidden() {
    Repositories repositories = mock(Repositories.class);
    RepoPath repoPath = mock(RepoPath.class);

    ConfigurationModule configurationModule = pluginConfig(Severity.LOW, Severity.MEDIUM);

    PackageValidator validator = new PackageValidator(configurationModule, repositories);
    TestResult testResult = getTestResult(List.of(), List.of(Severity.MEDIUM));

    assertThrows(CancelException.class, () -> validator.validate(testResult, repoPath));
  }

  @Test
  void validate_licenseForceDownload_allowed() {
    Repositories repositories = mock(Repositories.class);
    RepoPath repoPath = mock(RepoPath.class);

    when(repositories.getProperty(repoPath, ISSUE_LICENSES_FORCE_DOWNLOAD.propertyKey())).thenReturn("true");

    ConfigurationModule configurationModule = pluginConfig(Severity.LOW, Severity.MEDIUM);

    PackageValidator validator = new PackageValidator(configurationModule, repositories);
    TestResult testResult = getTestResult(List.of(), List.of(Severity.MEDIUM));

    assertDoesNotThrow(() -> validator.validate(testResult, repoPath));
  }

  private static @NotNull ConfigurationModule pluginConfig(Severity vulnThreshold, Severity licenseThreshold) {
    Properties properties = new Properties();
    properties.setProperty(PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD.propertyKey(), vulnThreshold.getSeverityLevel());
    properties.setProperty(PluginConfiguration.SCANNER_LICENSE_THRESHOLD.propertyKey(), licenseThreshold.getSeverityLevel());
    return new ConfigurationModule(properties);
  }

  private static @NotNull TestResult getTestResult(List<Severity> vulnSeverities, List<Severity> licenseSeverities) {
    TestResult testResult = new TestResult();

    testResult.issues = new Issues();

    testResult.issues.vulnerabilities = vulnSeverities.stream().map(severity -> {
      Vulnerability vuln = new Vulnerability();
      vuln.severity = severity;
      return vuln;
    }).collect(Collectors.toList());

    testResult.issues.licenses = licenseSeverities.stream().map(severity -> {
      Issue issue = new Vulnerability();
      issue.severity = severity;
      return issue;
    }).collect(Collectors.toList());
    return testResult;
  }


}
