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
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

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
    Map<Severity, Long> vulnCounts = getSeverityCounts(testResult.issues.vulnerabilities);
    Map<Severity, Long> licenseCounts = getSeverityCounts(testResult.issues.licenses);

    updateProperties(repoPath, testResult, vulnCounts, licenseCounts);
    validateVulnerabilityIssues(vulnCounts, repoPath);
    validateLicenseIssues(licenseCounts, repoPath);
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

  private void updateProperties(RepoPath repoPath, TestResult testResult, Map<Severity, Long> vulnCounts, Map<Severity, Long> licenseCounts) {
    repositories.setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), getSeverityCountsAsFormattedString(vulnCounts));
    repositories.setProperty(repoPath, ISSUE_LICENSES.propertyKey(), getSeverityCountsAsFormattedString(licenseCounts));
    repositories.setProperty(repoPath, ISSUE_URL.propertyKey(), testResult.packageDetailsURL);
    repositories.setProperty(repoPath, ISSUE_UPDATED_AT.propertyKey(), Instant.now().toString());

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

  private String getSeverityCountsAsFormattedString(@Nonnull Map<Severity, Long> counts) {
    return counts.entrySet().stream()
      .sorted((a, b) -> b.getKey().ordinal() - a.getKey().ordinal())
      .map(entry -> entry.getValue() + " " + entry.getKey().getSeverityLevel())
      .collect(Collectors.joining(", "));
  }

  private static Map<Severity, Long> getSeverityCounts(@Nonnull List<? extends Issue> issues) {
    return Arrays.stream(Severity.values())
      .collect(Collectors.toMap(
        severity -> severity,
        severity -> getSeverityCount(issues, severity))
      );
  }

  private static Long getSeverityCount(List<? extends Issue> issues, Severity severity) {
    return issues.stream()
      .filter(issue -> issue.severity == severity)
      .filter(distinctByKey(issue -> issue.id))
      .count();
  }

  private void validateVulnerabilityIssues(Map<Severity, Long> counts, RepoPath repoPath) {
    validateIssues(
      counts,
      Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD)),
      ISSUE_VULNERABILITIES_FORCE_DOWNLOAD,
      "vulnerabilities",
      repoPath
    );
  }

  private void validateLicenseIssues(Map<Severity, Long> counts, RepoPath repoPath) {
    validateIssues(
      counts,
      Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_LICENSE_THRESHOLD)),
      ISSUE_LICENSES_FORCE_DOWNLOAD,
      "license issues",
      repoPath
    );
  }

  private void validateIssues(Map<Severity, Long> counts, Severity threshold, ArtifactProperty forceDownloadProperty, String type, RepoPath repoPath) {
    final String forceDownloadKey = forceDownloadProperty.propertyKey();
    final String forceDownloadValue = repositories.getProperty(repoPath, forceDownloadKey);
    if ("true".equalsIgnoreCase(forceDownloadValue)) {
      LOG.debug("Allowing download. Artifact Property \"{}\" is \"true\". {}", repoPath, forceDownloadKey);
      return;
    }

    Long count = sumCounts(counts, threshold);
    if (count > 0) {
      throw new CancelException(format("Artifact has %s %s above %s threshold. %s", count, type, threshold.getSeverityLevel(), repoPath), 403);
    }
  }

  private static Long sumCounts(Map<Severity, Long> counts, Severity threshold) {
    return Arrays.stream(Severity.values())
      .filter(severity -> severity.ordinal() >= threshold.ordinal())
      .mapToLong(severity -> counts.getOrDefault(severity, 0L))
      .sum();
  }
}
