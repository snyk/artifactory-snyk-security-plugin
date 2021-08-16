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
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.*;
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
    String path = Optional.ofNullable(repoPath.getPath())
      .orElseThrow(() -> new CannotScanException("Path not provided."));

    PackageScanner scanner = getScannerForPackageType(path);
    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);

    TestResult testResult = scanner.scan(fileLayoutInfo, repoPath);
    updateProperties(repoPath, testResult);
    validateVulnerabilityIssues(testResult, repoPath);
    validateLicenseIssues(testResult, repoPath);
  }

  protected PackageScanner getScannerForPackageType(String path) {
    if (path.endsWith(".jar")) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_MAVEN).equals("true")) {
        return mavenScanner;
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_MAVEN.propertyKey()));
    }

    if (path.endsWith(".tgz")) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_NPM).equals("true")) {
        return npmScanner;
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_NPM.propertyKey()));
    }

    if (path.endsWith(".whl") || path.endsWith(".tar.gz") || path.endsWith(".zip") || path.endsWith(".egg")) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_PYPI).equals("true")) {
        return pythonScanner;
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_PYPI.propertyKey()));
    }

    throw new CannotScanException("Artifact is not supported.");
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
    validateIssues(
      testResult.issues.vulnerabilities,
      Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD)),
      ISSUE_VULNERABILITIES_FORCE_DOWNLOAD,
      "vulnerabilities",
      repoPath
    );
  }

  protected void validateLicenseIssues(TestResult testResult, RepoPath repoPath) {
    validateIssues(
      testResult.issues.licenses,
      Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_LICENSE_THRESHOLD)),
      ISSUE_LICENSES_FORCE_DOWNLOAD,
      "license issues",
      repoPath
    );
  }

  private void validateIssues(List<? extends Issue> issues, Severity threshold, ArtifactProperty forceDownloadProperty, String type, RepoPath repoPath) {
    final String forceDownloadKey = forceDownloadProperty.propertyKey();
    final String forceDownloadValue = repositories.getProperty(repoPath, forceDownloadKey);
    if ("true".equalsIgnoreCase(forceDownloadValue)) {
      LOG.debug("Allowing download. Artifact Property \"{}\" is \"true\". {}", repoPath, forceDownloadKey);
      return;
    }

    if (threshold == Severity.LOW) {
      if (!issues.isEmpty()) {
        throw new CancelException(format("Artifact has %s. %s", type, repoPath), 403);
      }
    } else if (threshold == Severity.MEDIUM) {
      long count = issues.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH || vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        throw new CancelException(format("Artifact has %s with medium, high or critical severity. %s", type, repoPath), 403);
      }
    } else if (threshold == Severity.HIGH) {
      long count = issues.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.HIGH || vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        throw new CancelException(format("Artifact has %s with high or critical severity. %s", type, repoPath), 403);
      }
    } else if (threshold == Severity.CRITICAL) {
      long count = issues.stream()
        .filter(vulnerability -> vulnerability.severity == Severity.CRITICAL)
        .count();
      if (count > 0) {
        throw new CancelException(format("Artifact has %s with critical severity. %s", type, repoPath), 403);
      }
    }
  }
}
