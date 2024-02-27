package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.ScanResponse;
import io.snyk.sdk.model.v1.TestResult;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;

import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.*;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class ScannerModule {

  private static final Logger LOG = LoggerFactory.getLogger(ScannerModule.class);
  private final ConfigurationModule configurationModule;
  private final Repositories repositories;
  private final String pluginVersion;

  public ScannerModule(@Nonnull ConfigurationModule configurationModule, @Nonnull Repositories repositories, String pluginVersion) {
    this.configurationModule = requireNonNull(configurationModule);
    this.repositories = requireNonNull(repositories);
    this.pluginVersion = pluginVersion;
  }

  public void scanArtifact(@Nonnull RepoPath repoPath) {
    //PackageScanner scanner = getScannerForPackageType(path, packageType);
    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);
    PackageScanner scanner = new ScannerFactory().createScanner(configurationModule, repositories, repoPath, pluginVersion);
    ScanResponse scanResponse = scanner.scan(fileLayoutInfo, repoPath);
    updateProperties(repoPath, scanResponse);
    LOG.debug("Snyk validating detected vulnerability issues");
    validateVulnerabilityIssues(scanResponse, repoPath);
    LOG.debug("Snyk validating detected license issues");
    // licenses results only applicable for V1 client-based scanners
    if (scanResponse instanceof TestResult) {
      validateLicenseIssues((TestResult) scanResponse, repoPath);
    }
  }

  protected void updateProperties(RepoPath repoPath, ScanResponse scanResponse) {
    repositories.setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), getSecurityIssuesResult(scanResponse));
    repositories.setProperty(repoPath, ISSUE_LICENSES.propertyKey(), getLicenseIssuesResult(scanResponse));
    repositories.setProperty(repoPath, ISSUE_URL.propertyKey(), scanResponse.getPackageDetailsUrl());

    setDefaultArtifactProperty(repoPath, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD, "false");
    setDefaultArtifactProperty(repoPath, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO, "");
    setDefaultArtifactProperty(repoPath, ISSUE_LICENSES_FORCE_DOWNLOAD, "false");
    setDefaultArtifactProperty(repoPath, ISSUE_LICENSES_FORCE_DOWNLOAD_INFO, "");
  }

  private void setDefaultArtifactProperty(RepoPath repoPath, ArtifactProperty property, String value) {
    String key = property.propertyKey();
    if (!repositories.hasProperty(repoPath, key)) {
      repositories.setProperty(repoPath, key, value);
    }
  }

  private String getSecurityIssuesResult(ScanResponse response) {
    long criticalSevCount = response.getCountOfSecurityIssuesAtSeverity(Severity.CRITICAL);
    long highSevCount = response.getCountOfSecurityIssuesAtSeverity(Severity.HIGH);
    long medSevCount = response.getCountOfSecurityIssuesAtSeverity(Severity.MEDIUM);
    long lowSevCount = response.getCountOfSecurityIssuesAtSeverity(Severity.LOW);

    return format("%d critical, %d high, %d medium, %d low", criticalSevCount, highSevCount, medSevCount, lowSevCount);
  }

  private String getLicenseIssuesResult(ScanResponse response) {
    long criticalSevCount = response.getCountOfLicenseIssuesAtSeverity(Severity.CRITICAL);
    long highSevCount = response.getCountOfLicenseIssuesAtSeverity(Severity.HIGH);
    long medSevCount = response.getCountOfLicenseIssuesAtSeverity(Severity.MEDIUM);
    long lowSevCount = response.getCountOfLicenseIssuesAtSeverity(Severity.LOW);

    return format("%d critical, %d high, %d medium, %d low", criticalSevCount, highSevCount, medSevCount, lowSevCount);
  }

  protected void validateVulnerabilityIssues(ScanResponse scanResponse, RepoPath repoPath) {
    final String vulnerabilitiesForceDownloadProperty = ISSUE_VULNERABILITIES_FORCE_DOWNLOAD.propertyKey();
    final String vulnerabilitiesForceDownload = repositories.getProperty(repoPath, vulnerabilitiesForceDownloadProperty);
    final boolean forceDownload = "true".equalsIgnoreCase(vulnerabilitiesForceDownload);
    if (forceDownload) {
      LOG.debug("Allowing download. Artifact Property \"{}\" is \"true\". {}", vulnerabilitiesForceDownloadProperty, repoPath);
      return;
    }

    Severity vulnerabilityThreshold = Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD));
    long issuesAtOrAboveThresholdCount = scanResponse.getCountOfSecurityIssuesAtOrAboveSeverity(vulnerabilityThreshold);

    if (issuesAtOrAboveThresholdCount > 0) {
      LOG.debug("Found {} vulnerabilities in {} returning 403", issuesAtOrAboveThresholdCount, repoPath);

      if (vulnerabilityThreshold == Severity.LOW) {
        throw new CancelException(format("Artifact has vulnerabilities. %s", repoPath), 403);
      } else if (vulnerabilityThreshold == Severity.MEDIUM) {
        throw new CancelException(format("Artifact has vulnerabilities with medium, high or critical severity. %s", repoPath), 403);
      } else if (vulnerabilityThreshold == Severity.HIGH) {
        throw new CancelException(format("Artifact has vulnerabilities with high or critical severity. %s", repoPath), 403);
      } else if (vulnerabilityThreshold == Severity.CRITICAL) {
        throw new CancelException(format("Artifact has vulnerabilities with critical severity. %s", repoPath), 403);
      }
    }
  }

  protected void validateLicenseIssues(TestResult testResult, RepoPath repoPath) {
    final String licensesForceDownloadProperty = ISSUE_LICENSES_FORCE_DOWNLOAD.propertyKey();
    final String licensesForceDownload = repositories.getProperty(repoPath, licensesForceDownloadProperty);
    final boolean forceDownload = "true".equalsIgnoreCase(licensesForceDownload);
    if (forceDownload) {
      LOG.debug("Allowing download. Artifact Property \"{}\" is \"true\". {}", repoPath, licensesForceDownloadProperty);
      return;
    }

    Severity licensesThreshold = Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_LICENSE_THRESHOLD));
    long issuesAtOrAboveThresholdCount = testResult.getCountOfLicenseIssuesAtOrAboveSeverity(licensesThreshold);

    if (issuesAtOrAboveThresholdCount > 0) {
      LOG.debug("Found {} license issues in {} returning 403", issuesAtOrAboveThresholdCount, repoPath);

      if (licensesThreshold == Severity.LOW) {
        throw new CancelException(format("Artifact has license issues. %s", repoPath), 403);
      } else if (licensesThreshold == Severity.MEDIUM) {
        throw new CancelException(format("Artifact has license issues with medium, high or critical severity. %s", repoPath), 403);
      } else if (licensesThreshold == Severity.HIGH) {
        throw new CancelException(format("Artifact has license issues with high or critical severity. %s", repoPath), 403);
      } else if (licensesThreshold == Severity.CRITICAL) {
        throw new CancelException(format("Artifact has license issues with critical severity. %s", repoPath), 403);
      }
    }
  }
}
