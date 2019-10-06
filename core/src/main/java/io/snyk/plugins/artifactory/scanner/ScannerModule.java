package io.snyk.plugins.artifactory.scanner;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.List;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
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

import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_LICENSES;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_LICENSES_FORCE_DOWNLOAD;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_LICENSES_FORCE_DOWNLOAD_INFO;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_URL;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_VULNERABILITIES;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_VULNERABILITIES_FORCE_DOWNLOAD;
import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_BLOCK_ON_API_FAILURE;
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
    if (!isExtensionSupported(fileLayoutInfo)) {
      LOG.warn("Artifact '{}' will not be scanned, because the extension is not supported", repoPath);
      return;
    }

    TestResult testResult = null;
    String extension = fileLayoutInfo.getExt();
    if ("jar".equals(extension)) {
      testResult = mavenScanner.scan(fileLayoutInfo);
    } else if ("tgz".equals(extension)) {
      testResult = npmScanner.scan(fileLayoutInfo);
    } else if ("whl".equals(extension) || "tar.gz".equals(extension) || "zip".equals(extension) || "egg".equals(extension)) {
      testResult = pythonScanner.scan(fileLayoutInfo);
    }

    if (testResult == null) {
      final String blockOnApiFailurePropertyKey = SCANNER_BLOCK_ON_API_FAILURE.propertyKey();
      final String blockOnApiFailure = configurationModule.getPropertyOrDefault(SCANNER_BLOCK_ON_API_FAILURE);
      if ("true".equals(blockOnApiFailure)) {
        throw new CancelException(format("Artifact '%s' could not be scanned because Snyk API is not available", repoPath), 500);
      } else {
        LOG.warn("Property '{}' is false, so we allow to download the artifact '{}'", blockOnApiFailurePropertyKey, repoPath);
        return;
      }
    }

    updateProperties(repoPath, fileLayoutInfo, testResult);

    validateVulnerabilityIssues(testResult, repoPath);
    validateLicenseIssues(testResult, repoPath);
  }

  private boolean isExtensionSupported(FileLayoutInfo fileLayoutInfo) {
    if (fileLayoutInfo == null) {
      return false;
    }
    List<String> supportedExtensions = Arrays.asList("jar", "tgz", "whl", "tar.gz", "zip", "egg");
    return supportedExtensions.contains(fileLayoutInfo.getExt());
  }

  private void updateProperties(RepoPath repoPath, FileLayoutInfo fileLayoutInfo, TestResult testResult) {
    String issueVulnerabilitiesProperty = repositories.getProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey());
    if (issueVulnerabilitiesProperty != null && !issueVulnerabilitiesProperty.isEmpty()) {
      LOG.debug("Skip updating properties for already scanned artifact: {}", repoPath);
      return;
    }

    StringBuilder snykIssueUrl = new StringBuilder("https://snyk.io/vuln/");
    if ("maven".equals(testResult.packageManager)) {
      snykIssueUrl.append("maven:")
                  .append(fileLayoutInfo.getOrganization()).append("%3A")
                  .append(fileLayoutInfo.getModule()).append("@")
                  .append(fileLayoutInfo.getBaseRevision());
    } else if ("npm".equals(testResult.packageManager)) {
      snykIssueUrl.append("npm:")
                  .append(fileLayoutInfo.getModule()).append("@")
                  .append(fileLayoutInfo.getBaseRevision());
    } else if ("pip".equals(testResult.packageManager)) {
      snykIssueUrl.append("pip:")
                  .append(fileLayoutInfo.getModule()).append("@")
                  .append(fileLayoutInfo.getBaseRevision());
    }

    repositories.setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), getIssuesAsFormattedString(testResult.issues.vulnerabilities));
    repositories.setProperty(repoPath, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD.propertyKey(), "false");
    repositories.setProperty(repoPath, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO.propertyKey(), "");
    repositories.setProperty(repoPath, ISSUE_LICENSES.propertyKey(), getIssuesAsFormattedString(testResult.issues.licenses));
    repositories.setProperty(repoPath, ISSUE_LICENSES_FORCE_DOWNLOAD.propertyKey(), "false");
    repositories.setProperty(repoPath, ISSUE_LICENSES_FORCE_DOWNLOAD_INFO.propertyKey(), "");
    repositories.setProperty(repoPath, ISSUE_URL.propertyKey(), snykIssueUrl.toString());
  }

  private String getIssuesAsFormattedString(@Nonnull List<? extends Issue> issues) {
    long countHighSeverities = issues.stream().filter(issue -> issue.severity == Severity.HIGH).count();
    long countMediumSeverities = issues.stream().filter(issue -> issue.severity == Severity.MEDIUM).count();
    long countLowSeverities = issues.stream().filter(issue -> issue.severity == Severity.LOW).count();

    return format("%d high, %d medium, %d low", countHighSeverities, countMediumSeverities, countLowSeverities);
  }

  private void validateVulnerabilityIssues(TestResult testResult, RepoPath repoPath) {
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
                                                    .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH)
                                                    .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities with severity medium or high", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.HIGH) {
      long count = testResult.issues.vulnerabilities.stream()
                                                    .filter(vulnerability -> vulnerability.severity == Severity.HIGH)
                                                    .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities with severity high", repoPath), 403);
      }
    }
  }

  private void validateLicenseIssues(TestResult testResult, RepoPath repoPath) {
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
