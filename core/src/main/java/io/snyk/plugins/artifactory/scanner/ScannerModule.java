package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.TestResult;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.*;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_BLOCK_ON_API_FAILURE;
import static io.snyk.sdk.util.Predicates.distinctByKey;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class ScannerModule {

  private static final Logger LOG = LoggerFactory.getLogger(ScannerModule.class);

  private final ConfigurationModule configurationModule;
  private final Repositories repositories;
  private final MavenScanner mavenScanner;
  private final NpmScanner npmScanner;
  private final PythonScanner pythonScanner;

  public ScannerModule(@Nonnull ConfigurationModule configurationModule, @Nonnull Repositories repositories, @Nonnull SnykClient snykClient) {
    this.configurationModule = requireNonNull(configurationModule);
    this.repositories = requireNonNull(repositories);

    mavenScanner = new MavenScanner(configurationModule, snykClient);
    npmScanner = new NpmScanner(configurationModule, snykClient);
    pythonScanner = new PythonScanner(configurationModule, snykClient);
  }

  public void scanArtifact(@Nonnull RepoPath repoPath) {
    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);

    String path = repoPath.getPath();
    if (path == null) {
      throw new CannotScanException("Artifact path is not available");
    }

    Optional<PackageScanner> maybeScanner = getScannerForPackageType(path);
    if (maybeScanner.isEmpty()) {
      throw new CannotScanException("Artifact not supported.");
    }

    var scanner = maybeScanner.get();
    var maybeTestResult = scanner.scan(fileLayoutInfo, repoPath);
    if (maybeTestResult.isEmpty()) {
      final String blockOnApiFailurePropertyKey = SCANNER_BLOCK_ON_API_FAILURE.propertyKey();
      final String blockOnApiFailure = configurationModule.getPropertyOrDefault(SCANNER_BLOCK_ON_API_FAILURE);
      String message = format("Artifact '%s' could not be scanned because Snyk API is not available", repoPath);
      if ("true".equals(blockOnApiFailure)) {
        throw new CancelException(message, 500);
      }
      LOG.warn(message);
      LOG.warn("Property '{}' is false, so allowing download: '{}'", blockOnApiFailurePropertyKey, repoPath);
      throw new CannotScanException("Snyk API request failed.");
    }

    TestResult testResult = maybeTestResult.get();
    updateProperties(repoPath, testResult);
    validateVulnerabilityIssues(testResult, repoPath);
    validateLicenseIssues(testResult, repoPath);
  }

  protected Optional<PackageScanner> getScannerForPackageType(String path) {
    if (path.endsWith(".jar")) {
      return Optional.of(mavenScanner);
    } else if (path.endsWith(".tgz")) {
      return Optional.of(npmScanner);
    } else if (path.endsWith(".whl") || path.endsWith(".tar.gz") || path.endsWith(".zip") || path.endsWith(".egg")) {
      return Optional.of(pythonScanner);
    } else {
      return Optional.empty();
    }
  }

  protected void updateProperties(RepoPath repoPath, TestResult testResult) {
    repositories.setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), getIssuesAsFormattedString(testResult.issues.vulnerabilities));
    repositories.setProperty(repoPath, ISSUE_LICENSES.propertyKey(), getIssuesAsFormattedString(testResult.issues.licenses));
    repositories.setProperty(repoPath, ISSUE_URL.propertyKey(), testResult.packageDetailsURL);

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

  private String getIssuesAsFormattedString(@Nonnull List<? extends Issue> issues) {
    long countCriticalSeverities = issues.stream()
      .filter(issue -> issue.severity == Severity.CRITICAL)
      .filter(distinctByKey(issue -> issue.id))
      .count();
    long countHighSeverities = issues.stream()
      .filter(issue -> issue.severity == Severity.HIGH)
      .filter(distinctByKey(issue -> issue.id))
      .count();
    long countMediumSeverities = issues.stream()
      .filter(issue -> issue.severity == Severity.MEDIUM)
      .filter(distinctByKey(issue -> issue.id))
      .count();
    long countLowSeverities = issues.stream()
      .filter(issue -> issue.severity == Severity.LOW)
      .filter(distinctByKey(issue -> issue.id))
      .count();

    return format("%d critical, %d high, %d medium, %d low", countCriticalSeverities, countHighSeverities, countMediumSeverities, countLowSeverities);
  }

  protected void validateVulnerabilityIssues(TestResult testResult, RepoPath repoPath) {
    final String vulnerabilitiesForceDownloadProperty = ISSUE_VULNERABILITIES_FORCE_DOWNLOAD.propertyKey();
    final String vulnerabilitiesForceDownload = repositories.getProperty(repoPath, vulnerabilitiesForceDownloadProperty);
    final boolean forceDownload = "true".equalsIgnoreCase(vulnerabilitiesForceDownload);
    if (forceDownload) {
      LOG.info("Property '{}' is true, so we allow to download artifact: {}", vulnerabilitiesForceDownloadProperty, repoPath);
      return;
    }

    Severity vulnerabilityThreshold = Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD));
    if (vulnerabilityThreshold == Severity.LOW) {
      if (!testResult.issues.vulnerabilities.isEmpty()) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.MEDIUM) {
      long count = testResult.issues.vulnerabilities.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH || vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities with severity medium or high or critical", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.HIGH) {
      long count = testResult.issues.vulnerabilities.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.HIGH || vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities with severity high or critical", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.CRITICAL) {
      long count = testResult.issues.vulnerabilities.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities with severity critical", repoPath), 403);
      }
    }
  }

  protected void validateLicenseIssues(TestResult testResult, RepoPath repoPath) {
    final String licensesForceDownloadProperty = ISSUE_LICENSES_FORCE_DOWNLOAD.propertyKey();
    final String licensesForceDownload = repositories.getProperty(repoPath, licensesForceDownloadProperty);
    final boolean forceDownload = "true".equalsIgnoreCase(licensesForceDownload);
    if (forceDownload) {
      LOG.info("Property '{}' is true, so we allow to download artifact: {}", licensesForceDownloadProperty, repoPath);
      return;
    }

    Severity licensesThreshold = Severity.of(configurationModule.getProperty(PluginConfiguration.SCANNER_LICENSE_THRESHOLD));
    if (licensesThreshold == Severity.LOW) {
      if (!testResult.issues.licenses.isEmpty()) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities (type 'licenses')", repoPath), 403);
      }
    } else if (licensesThreshold == Severity.MEDIUM) {
      long count = testResult.issues.licenses.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH)
        .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities (type 'licenses') with severity medium or high", repoPath), 403);
      }
    } else if (licensesThreshold == Severity.HIGH) {
      long count = testResult.issues.licenses.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.HIGH)
        .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities (type 'licenses') with severity high", repoPath), 403);
      }
    }
  }
}
