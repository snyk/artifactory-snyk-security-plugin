package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.api.rest.SnykRestClient;
import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.ScanResponse;
import io.snyk.sdk.model.TestResult;
import io.snyk.sdk.model.rest.PurlIssue;
import io.snyk.sdk.model.rest.PurlIssues;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
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
  // TODO: refactor to scanner factory pattern
  private final ConfigurationModule configurationModule;
  private final Repositories repositories;
  private final MavenScanner mavenScanner;
  private final NpmScanner npmScanner;
  private final PythonScanner pythonScanner;
  private PurlScanner cocoapodsScanner;
  private PurlScanner nugetScanner;

  public ScannerModule(@Nonnull ConfigurationModule configurationModule, @Nonnull Repositories repositories, @Nonnull SnykV1Client snykV1Client) {
    this.configurationModule = requireNonNull(configurationModule);
    this.repositories = requireNonNull(repositories);

    mavenScanner = new MavenScanner(configurationModule, snykV1Client);
    npmScanner = new NpmScanner(configurationModule, snykV1Client);
    pythonScanner = new PythonScanner(configurationModule, snykV1Client);
  }

  public ScannerModule(@Nonnull ConfigurationModule configurationModule, @Nonnull Repositories repositories, @Nonnull SnykV1Client snykV1Client, @Nonnull SnykRestClient snykRestClient) {
    this.configurationModule = requireNonNull(configurationModule);
    this.repositories = requireNonNull(repositories);

    mavenScanner = new MavenScanner(configurationModule, snykV1Client);
    npmScanner = new NpmScanner(configurationModule, snykV1Client);
    pythonScanner = new PythonScanner(configurationModule, snykV1Client);
    cocoapodsScanner = new PurlScanner(configurationModule, repositories, snykRestClient);
    nugetScanner = new PurlScanner(configurationModule, repositories, snykRestClient);
  }

  public void scanArtifact(@Nonnull RepoPath repoPath) {
    String path = Optional.ofNullable(repoPath.getPath())
      .orElseThrow(() -> new CannotScanException("Path not provided."));

    RepositoryConfiguration repoConf = repositories.getRepositoryConfiguration(repoPath.getRepoKey());
    String packageType = requireNonNull(repoConf).getPackageType();
    PackageScanner scanner = getScannerForPackageType(path, packageType);
    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);
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

  protected PackageScanner getScannerForPackageType(String path, String packageType) {
    LOG.debug(format("Snyk determining scanner for packageType: %s, path: " + packageType, path));
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

    if (packageType.equalsIgnoreCase("pypi") && (path.endsWith(".whl") || path.endsWith(".tar.gz") || path.endsWith(".zip") || path.endsWith(".egg"))) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_PYPI).equals("true")) {
        return pythonScanner;
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_PYPI.propertyKey()));
    }

    if (packageType.equalsIgnoreCase("cocoapods") && (path.endsWith(".tar.gz") || path.endsWith(".zip"))) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_COCOAPODS).equals("true")) {
        LOG.debug("Snyk launching cocoapods scanner");
        return cocoapodsScanner;
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_COCOAPODS.propertyKey()));
    }

    if (path.endsWith(".nupkg")) {
      if (configurationModule.getPropertyOrDefault(SCANNER_PACKAGE_TYPE_NUGET).equals("true")) {
        LOG.debug("Snyk launching nuget scanner");
        return nugetScanner;
      }
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", SCANNER_PACKAGE_TYPE_NUGET.propertyKey()));
    }

    throw new CannotScanException("Artifact is not supported.");
  }

  protected void updateProperties(RepoPath repoPath, ScanResponse scanResponse) {
    if (scanResponse instanceof TestResult) {
      LOG.debug("Synk updating with test api result properties");
      TestResult testResult = (TestResult) scanResponse;
      repositories.setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), getIssuesAsFormattedString(testResult.issues.vulnerabilities));
      repositories.setProperty(repoPath, ISSUE_LICENSES.propertyKey(), getIssuesAsFormattedString(testResult.issues.licenses));
      repositories.setProperty(repoPath, ISSUE_URL.propertyKey(), testResult.packageDetailsURL);
    } else if (scanResponse instanceof PurlIssues) {
      LOG.debug("Synk updating with PURL issues properties");
      // PurlScanner through list-issues-for-a-package REST API returns only package_vulnerability issues
      PurlIssues purlIssues = (PurlIssues) scanResponse;
      repositories.setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), evalPurlIssuesBySeverity(purlIssues.purlIssues));
      repositories.setProperty(repoPath, ISSUE_URL.propertyKey(), purlIssues.packageDetailsURL);
    }

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

  private String evalPurlIssuesBySeverity(@Nonnull List<? extends PurlIssue> issues) {
    long countCriticalSeverities = issues.stream()
      .filter(issue -> issue.attribute.effective_severity_level == Severity.CRITICAL)
      .filter(distinctByKey(issue -> issue.attribute.key))
      .count();
    long countHighSeverities = issues.stream()
      .filter(issue -> issue.attribute.effective_severity_level == Severity.HIGH)
      .filter(distinctByKey(issue -> issue.attribute.key))
      .count();
    long countMediumSeverities = issues.stream()
      .filter(issue -> issue.attribute.effective_severity_level == Severity.MEDIUM)
      .filter(distinctByKey(issue -> issue.attribute.key))
      .count();
    long countLowSeverities = issues.stream()
      .filter(issue -> issue.attribute.effective_severity_level == Severity.LOW)
      .filter(distinctByKey(issue -> issue.attribute.key))
      .count();

    return format("%d critical, %d high, %d medium, %d low", countCriticalSeverities, countHighSeverities, countMediumSeverities, countLowSeverities);
  }

  // TODO: refactor to decorator pattern
  protected void validateVulnerabilityIssues(ScanResponse scanResponse, RepoPath repoPath) {
    final String vulnerabilitiesForceDownloadProperty = ISSUE_VULNERABILITIES_FORCE_DOWNLOAD.propertyKey();
    final String vulnerabilitiesForceDownload = repositories.getProperty(repoPath, vulnerabilitiesForceDownloadProperty);
    final boolean forceDownload = "true".equalsIgnoreCase(vulnerabilitiesForceDownload);
    if (forceDownload) {
      LOG.debug("Allowing download. Artifact Property \"{}\" is \"true\". {}", vulnerabilitiesForceDownloadProperty, repoPath);
      return;
    }

    Severity vulnerabilityThreshold = Severity.of(configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_VULNERABILITY_THRESHOLD));
    if (vulnerabilityThreshold == Severity.LOW) {
      if ((scanResponse instanceof TestResult && !(((TestResult) scanResponse).issues.vulnerabilities.isEmpty())) ||
        (scanResponse instanceof PurlIssues && !(((PurlIssues) scanResponse).purlIssues.isEmpty()))) {
        LOG.debug("Found vulnerabilities in {} returning 403", repoPath);
        throw new CancelException(format("Artifact has vulnerabilities. %s", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.MEDIUM) {
      long count = 0;
      if (scanResponse instanceof TestResult) {
        TestResult testResult = (TestResult) scanResponse;
        count = testResult.issues.vulnerabilities.stream()
          .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH || vulnerability.severity == Severity.CRITICAL)
          .count();
      } else if (scanResponse instanceof PurlIssues) {
        PurlIssues purlIssues = (PurlIssues) scanResponse;
        count = purlIssues.purlIssues.stream()
          .filter(issue -> issue.attribute.effective_severity_level == Severity.MEDIUM || issue.attribute.effective_severity_level == Severity.HIGH || issue.attribute.effective_severity_level == Severity.CRITICAL)
          .count();
      }
      if (count > 0) {
        LOG.debug("Found {} vulnerabilities in {} returning 403", count, repoPath);
        throw new CancelException(format("Artifact has vulnerabilities with medium, high or critical severity. %s", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.HIGH) {
      long count = 0;
      if (scanResponse instanceof TestResult) {
        TestResult testResult = (TestResult) scanResponse;
        count = testResult.issues.vulnerabilities.stream()
          .filter(vulnerability -> vulnerability.severity == Severity.HIGH || vulnerability.severity == Severity.CRITICAL)
          .count();
      } else if (scanResponse instanceof PurlIssues) {
        PurlIssues purlIssues = (PurlIssues) scanResponse;
        count = purlIssues.purlIssues.stream()
          .filter(issue -> issue.attribute.effective_severity_level == Severity.HIGH || issue.attribute.effective_severity_level == Severity.CRITICAL)
          .count();
      }
      if (count > 0) {
        LOG.debug("Found {}, vulnerabilities in {} returning 403", count, repoPath);
        throw new CancelException(format("Artifact has vulnerabilities with high or critical severity. %s", repoPath), 403);
      }
    } else if (vulnerabilityThreshold == Severity.CRITICAL) {
      long count = 0;
      if (scanResponse instanceof TestResult) {
        TestResult testResult = (TestResult) scanResponse;
        count = testResult.issues.vulnerabilities.stream()
          .filter(vulnerability -> vulnerability.severity == Severity.CRITICAL)
          .count();
      } else if (scanResponse instanceof PurlIssues) {
        PurlIssues purlIssues = (PurlIssues) scanResponse;
        count = purlIssues.purlIssues.stream()
          .filter(issue -> issue.attribute.effective_severity_level == Severity.CRITICAL)
          .count();
      }
      if (count > 0) {
        LOG.debug("Found {} vulnerabilities in {} returning 403", count, repoPath);
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
