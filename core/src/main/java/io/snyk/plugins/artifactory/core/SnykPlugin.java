package io.snyk.plugins.artifactory.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Properties;

import io.snyk.plugins.artifactory.core.scanner.MavenScanner;
import io.snyk.plugins.artifactory.core.scanner.NpmScanner;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.TestResult;
import io.snyk.sdk.model.Vulnerability;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class SnykPlugin {
  private static final Logger LOG = LoggerFactory.getLogger(SnykPlugin.class);

  private final Repositories repositories;
  private final Properties properties;
  private final SnykClient snykClient;
  private final MavenScanner mavenScanner;
  private final NpmScanner npmScanner;

  public SnykPlugin(Repositories repositories, File pluginsDirectory) {
    this.repositories = requireNonNull(repositories);

    properties = getPropertyFile(pluginsDirectory.getAbsoluteFile());
    snykClient = getSnykClient(properties);
    mavenScanner = new MavenScanner(properties, snykClient);
    npmScanner = new NpmScanner(properties, snykClient);

    LOG.info("snykPlugin configuration:");
    LOG.info("snyk.artifactory.scanner.vulnerability.threshold: {}", properties.getProperty("snyk.artifactory.scanner.vulnerability.threshold"));
  }

  private Properties getPropertyFile(File pluginsDirectory) {
    final Properties properties = new Properties();
    File propertiesFile = new File(pluginsDirectory.getAbsoluteFile(), "snykSecurityPlugin.properties");
    try (final FileInputStream fis = new FileInputStream(propertiesFile)) {
      properties.load(fis);
    } catch (IOException ex) {
      LOG.error("Plugin properties could not be loaded", ex);
    }
    return properties;
  }

  private SnykClient getSnykClient(Properties properties) {
    return Snyk.newBuilder(new Snyk.Config(properties.getProperty("snyk.api.token"))).buildSync();
  }

  public void handleBeforeDownloadEvent(RepoPath repoPath) {
    LOG.debug("Handle 'beforeDownload' event for: {}", repoPath);

    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);

    boolean allowDownload = false;
    String allowDownloadProperty = repositories.getProperty(repoPath, "snyk.scanner.forceDownload");
    if (allowDownloadProperty != null) {
      allowDownload = "true".equalsIgnoreCase(allowDownloadProperty);
    }

    TestResult testResult;
    String extension = fileLayoutInfo.getExt();
    if ("jar".equals(extension)) {
      testResult = mavenScanner.scan(fileLayoutInfo);
      updateProperties(repoPath, fileLayoutInfo, testResult);

      if (allowDownload) {
        LOG.info("Property 'snyk.scanner.forceDownload' is true, so we allow to download artifact: {}", repoPath);
        return;
      }

      validateSeverityThreshold(testResult, repoPath);
    } else if ("tgz".equals(extension)) {
      testResult = npmScanner.performScan(fileLayoutInfo);
      updateProperties(repoPath, fileLayoutInfo, testResult);

      if (allowDownload) {
        LOG.info("Property 'snyk.scanner.forceDownload' is true, so we allow to download artifact: {}", repoPath);
        return;
      }

      validateSeverityThreshold(testResult, repoPath);
    }

  }

  private void updateProperties(RepoPath repoPath, FileLayoutInfo fileLayoutInfo, TestResult testResult) {
    String vulnerabilityCount = repositories.getProperty(repoPath, "snyk.scanner.vulnerabilities");
    if (vulnerabilityCount != null && !vulnerabilityCount.isEmpty()) {
      LOG.debug("Skip already scanned artifact: {}", repoPath);
      return;
    }

    repositories.setProperty(repoPath, "snyk.scanner.forceDownload", "false");
    repositories.setProperty(repoPath, "snyk.scanner.forceDownload.info", "");
    repositories.setProperty(repoPath, "snyk.scanner.vulnerabilities", getVulnerabilitiesBySeverity(testResult.issues.vulnerabilities));
    repositories.setProperty(repoPath, "snyk.scanner.licenses", getLicencesBySeverity(testResult.issues.licenses));

    StringBuilder snykVulnerabilityUrl = new StringBuilder("https://snyk.io/vuln/");
    if ("maven".equals(testResult.packageManager)) {
      snykVulnerabilityUrl.append("maven:")
                          .append(fileLayoutInfo.getOrganization()).append("%3A")
                          .append(fileLayoutInfo.getModule()).append("@")
                          .append(fileLayoutInfo.getBaseRevision());
    } else if ("npm".equals(testResult.packageManager)) {
      snykVulnerabilityUrl.append("npm:")
                          .append(fileLayoutInfo.getModule()).append("@")
                          .append(fileLayoutInfo.getBaseRevision());
    }
    repositories.setProperty(repoPath, "snyk.vulnerability.url", snykVulnerabilityUrl.toString());
  }

  private String getVulnerabilitiesBySeverity(List<Vulnerability> issues) {
    long countOfHighVulnerabilities = issues.stream().filter(vulnerability -> vulnerability.severity == Severity.HIGH).count();
    long countOfMediumVulnerabilities = issues.stream().filter(vulnerability -> vulnerability.severity == Severity.MEDIUM).count();
    long countOfLowVulnerabilities = issues.stream().filter(vulnerability -> vulnerability.severity == Severity.LOW).count();

    return format("%d high, %d medium, %d low", countOfHighVulnerabilities, countOfMediumVulnerabilities, countOfLowVulnerabilities);
  }

  private String getLicencesBySeverity(List<Issue> issues) {
    long countOfHighVulnerabilities = issues.stream().filter(vulnerability -> vulnerability.severity == Severity.HIGH).count();
    long countOfMediumVulnerabilities = issues.stream().filter(vulnerability -> vulnerability.severity == Severity.MEDIUM).count();
    long countOfLowVulnerabilities = issues.stream().filter(vulnerability -> vulnerability.severity == Severity.LOW).count();

    return format("%d high, %d medium, %d low", countOfHighVulnerabilities, countOfMediumVulnerabilities, countOfLowVulnerabilities);
  }

  private void validateSeverityThreshold(TestResult testResult, RepoPath repoPath) {
    Severity vulnerabilitiesThreshold = Severity.of(properties.getProperty("snyk.artifactory.scanner.vulnerability.threshold"));
    if (vulnerabilitiesThreshold == Severity.LOW) {
      if (!testResult.issues.vulnerabilities.isEmpty()) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities", repoPath), 403);
      }
    } else if (vulnerabilitiesThreshold == Severity.MEDIUM) {
      long count = testResult.issues.vulnerabilities.stream()
                                                    .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH)
                                                    .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities with severity medium or high", repoPath), 403);
      }
    } else if (vulnerabilitiesThreshold == Severity.HIGH) {
      long count = testResult.issues.vulnerabilities.stream()
                                                    .filter(vulnerability -> vulnerability.severity == Severity.HIGH)
                                                    .count();
      if (count > 0) {
        throw new CancelException(format("Artifact '%s' has vulnerabilities with severity high", repoPath), 403);
      }
    }

    Severity licensesThreshold = Severity.of(properties.getProperty("snyk.artifactory.scanner.license.threshold"));
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
