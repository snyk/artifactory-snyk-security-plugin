package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.properties.RepositoryArtifactProperties;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.*;
import io.snyk.sdk.api.v1.SnykClient;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import java.util.Optional;

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
    MonitoredArtifact artifact = resolveArtifact(repoPath);

    validateArtifact(artifact);
  }

  public MonitoredArtifact resolveArtifact(RepoPath repoPath) {
    return testArtifact(repoPath);
  }

  private @NotNull MonitoredArtifact testArtifact(RepoPath repoPath) {
    PackageScanner scanner = getScannerForPackageType(repoPath);
    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);
    TestResult testResult = scanner.scan(fileLayoutInfo, repoPath);
    MonitoredArtifact artifact = toMonitoredArtifact(testResult, repoPath);
    artifact.write(new RepositoryArtifactProperties(repoPath, repositories));
    return artifact;
  }

  private void validateArtifact(MonitoredArtifact artifact) {
    ValidationSettings validationSettings = ValidationSettings.from(configurationModule);
    PackageValidator validator = new PackageValidator(validationSettings);
    validator.validate(artifact);
  }

  private @NotNull MonitoredArtifact toMonitoredArtifact(TestResult testResult, @NotNull RepoPath repoPath) {
    Ignores ignores = Ignores.fromProperties(repositories, repoPath);
    return new MonitoredArtifact(repoPath.toString(), testResult, ignores);
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
}
