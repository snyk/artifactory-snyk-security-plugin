package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.Ignores;
import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.ValidationSettings;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import java.net.URI;
import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.*;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class ScannerModule {

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
    MonitoredArtifact artifact = testArtifact(repoPath);

    validateArtifact(artifact);
  }

  private @NotNull MonitoredArtifact testArtifact(RepoPath repoPath) {
    PackageScanner scanner = getScannerForPackageType(repoPath);
    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);
    TestResult testResult = scanner.scan(fileLayoutInfo, repoPath);
    MonitoredArtifact artifact = toMonitoredArtifact(testResult, repoPath);
    updateProperties(repoPath, artifact);
    return artifact;
  }

  private void validateArtifact(MonitoredArtifact artifact) {
    ValidationSettings validationSettings = ValidationSettings.from(configurationModule);
    PackageValidator validator = new PackageValidator(validationSettings);
    validator.validate(artifact);
  }

  private @NotNull MonitoredArtifact toMonitoredArtifact(TestResult testResult, @NotNull RepoPath repoPath) {
    IssueSummary vulns = IssueSummary.from(testResult.issues.vulnerabilities);
    IssueSummary licenses = IssueSummary.from(testResult.issues.licenses);
    Ignores ignores = Ignores.fromProperties(repositories, repoPath);
    return new MonitoredArtifact(repoPath.toString(), vulns, licenses, ignores, URI.create(testResult.packageDetailsURL));
  }

  protected PackageScanner getScannerForPackageType(RepoPath repoPath) {
    String path = Optional.ofNullable(repoPath.getPath())
      .orElseThrow(() -> new CannotScanException("Path not provided."));
    return getScannerForPackageType(path);
  }

  protected PackageScanner getScannerForPackageType(String path) {
    Ecosystem ecosystem = Ecosystem.fromPackagePath(path).orElseThrow(() -> new CannotScanException("Artifact is not supported."));
    if (!configurationModule.getPropertyOrDefault(ecosystem.getConfigProperty()).equals("true")) {
      throw new CannotScanException(format("Plugin Property \"%s\" is not \"true\".", ecosystem.getConfigProperty().propertyKey()));
    }

    switch (ecosystem) {
      case MAVEN:
        return mavenScanner;
      case NPM:
        return npmScanner;
      case PYPI:
        return pythonScanner;
      default:
        throw new IllegalStateException("Unsupported ecosystem: " + ecosystem.name());
    }
  }

  protected void updateProperties(RepoPath repoPath, MonitoredArtifact artifact) {
    repositories.setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), artifact.getVulnSummary().toString());
    repositories.setProperty(repoPath, ISSUE_LICENSES.propertyKey(), artifact.getLicenseSummary().toString());
    repositories.setProperty(repoPath, ISSUE_URL.propertyKey(), artifact.getDetailsUrl().toString());

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
}
