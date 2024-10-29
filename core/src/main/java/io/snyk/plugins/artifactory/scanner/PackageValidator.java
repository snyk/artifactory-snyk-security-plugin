package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.TestResult;
import org.artifactory.exception.CancelException;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_LICENSES_FORCE_DOWNLOAD;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_VULNERABILITIES_FORCE_DOWNLOAD;
import static java.lang.String.format;

public class PackageValidator {

  private static final Logger LOG = LoggerFactory.getLogger(PackageValidator.class);

  private final ConfigurationModule configurationModule;
  private final Repositories repositories;

  public PackageValidator(ConfigurationModule configurationModule, Repositories repositories) {
    this.configurationModule = configurationModule;
    this.repositories = repositories;
  }

  public void validate(TestResult testResult, RepoPath repoPath) {
    validateVulnerabilityIssues(testResult, repoPath);
    validateLicenseIssues(testResult, repoPath);
  }

  private void validateVulnerabilityIssues(TestResult testResult, RepoPath repoPath) {
    final String vulnerabilitiesForceDownloadProperty = ISSUE_VULNERABILITIES_FORCE_DOWNLOAD.propertyKey();
    final String vulnerabilitiesForceDownload = repositories.getProperty(repoPath, vulnerabilitiesForceDownloadProperty);
    final boolean forceDownload = "true".equalsIgnoreCase(vulnerabilitiesForceDownload);
    if (forceDownload) {
      LOG.debug("Allowing download. Artifact Property \"{}\" is \"true\". {}", vulnerabilitiesForceDownloadProperty, repoPath);
      return;
    }

    Severity vulnerabilityThreshold = Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD));
    if (vulnerabilityThreshold == Severity.LOW) {
      if (!testResult.issues.vulnerabilities.isEmpty()) {
        LOG.debug("Found vulnerabilities in {} returning 403", repoPath);
        throw new CancelException(format("Artifact has vulnerabilities. %s", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.MEDIUM) {
      long count = testResult.issues.vulnerabilities.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH || vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        LOG.debug("Found {} vulnerabilities in {} returning 403", count, repoPath);
        throw new CancelException(format("Artifact has vulnerabilities with medium, high or critical severity. %s", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.HIGH) {
      long count = testResult.issues.vulnerabilities.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.HIGH || vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        LOG.debug("Found {}, vulnerabilities in {} returning 403", count, repoPath);
        throw new CancelException(format("Artifact has vulnerabilities with high or critical severity. %s", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.CRITICAL) {
      long count = testResult.issues.vulnerabilities.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        LOG.debug("Found {} vulnerabilities in {} returning 403", count, repoPath);
        throw new CancelException(format("Artifact has vulnerabilities with critical severity. %s", repoPath), 403);
      }
    }
  }

  private void validateLicenseIssues(TestResult testResult, RepoPath repoPath) {
    final String licensesForceDownloadProperty = ISSUE_LICENSES_FORCE_DOWNLOAD.propertyKey();
    final String licensesForceDownload = repositories.getProperty(repoPath, licensesForceDownloadProperty);
    final boolean forceDownload = "true".equalsIgnoreCase(licensesForceDownload);
    if (forceDownload) {
      LOG.debug("Allowing download. Artifact Property \"{}\" is \"true\". {}", repoPath, licensesForceDownloadProperty);
      return;
    }

    Severity licensesThreshold = Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_LICENSE_THRESHOLD));
    if (licensesThreshold == Severity.LOW) {
      if (!testResult.issues.licenses.isEmpty()) {
        LOG.debug("Found license issues in {} returning 403", repoPath);
        throw new CancelException(format("Artifact has license issues. %s", repoPath), 403);
      }
    } else if (licensesThreshold == Severity.MEDIUM) {
      long count = testResult.issues.licenses.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH)
        .count();
      if (count > 0) {
        LOG.debug("Found {} license issues in {} returning 403", count, repoPath);
        throw new CancelException(format("Artifact has license issues with medium or high severity. %s", repoPath), 403);
      }
    } else if (licensesThreshold == Severity.HIGH) {
      long count = testResult.issues.licenses.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.HIGH)
        .count();
      if (count > 0) {
        LOG.debug("Found {} license issues in {} returning 403", count, repoPath);
        throw new CancelException(format("Artifact has license issues with high severity. %s", repoPath), 403);
      }
    }
  }

}
