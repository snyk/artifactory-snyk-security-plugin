package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.configuration.properties.RepositoryArtifactProperties;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.Ignores;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.model.ValidationSettings;
import io.snyk.sdk.api.v1.SnykClient;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.time.Duration;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class ScannerModule {
  private static final Logger LOG = LoggerFactory.getLogger(ScannerModule.class);
  private final ConfigurationModule configurationModule;
  private final Repositories repositories;
  private final MavenScanner mavenScanner;
  private final NpmScanner npmScanner;
  private final PythonScanner pythonScanner;
  private final ArtifactResolver artifactResolver;

  public ScannerModule(@Nonnull ConfigurationModule configurationModule, @Nonnull Repositories repositories, @Nonnull SnykClient snykClient) {
    this.configurationModule = requireNonNull(configurationModule);
    this.repositories = requireNonNull(repositories);

    mavenScanner = new MavenScanner(configurationModule, snykClient);
    npmScanner = new NpmScanner(configurationModule, snykClient);
    pythonScanner = new PythonScanner(configurationModule, snykClient);

    artifactResolver = shouldTestContinuously() ? new ArtifactCache(
      durationHoursProperty(PluginConfiguration.TEST_FREQUENCY_HOURS, configurationModule),
      durationHoursProperty(PluginConfiguration.EXTEND_TEST_DEADLINE_HOURS, configurationModule)
    ) : new ReadOnlyArtifactResolver();
  }

  public Optional<MonitoredArtifact> testArtifact(@Nonnull RepoPath repoPath) {
    return runTest(repoPath).map(artifact -> artifact.write(properties(repoPath)));
  }

  public void filterAccess(@Nonnull RepoPath repoPath) {
    resolveArtifact(repoPath)
      .ifPresentOrElse(
        this::filter,
        () -> LOG.info("No vulnerability info found for {}", repoPath)
      );
  }

  private Optional<MonitoredArtifact> resolveArtifact(RepoPath repoPath) {
    return artifactResolver.get(properties(repoPath), () -> runTest(repoPath));
  }

  private ArtifactProperties properties(RepoPath repoPath) {
    return new RepositoryArtifactProperties(repoPath, repositories);
  }

  private @NotNull Optional<MonitoredArtifact> runTest(RepoPath repoPath) {
    return getScannerForPackageType(repoPath).map(scanner -> runTestWith(scanner, repoPath));
  }

  private MonitoredArtifact runTestWith(PackageScanner scanner, RepoPath repoPath) {
    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);
    TestResult testResult = scanner.scan(fileLayoutInfo, repoPath);
    return toMonitoredArtifact(testResult, repoPath);
  }

  private void filter(MonitoredArtifact artifact) {
    ValidationSettings validationSettings = ValidationSettings.from(configurationModule);
    PackageValidator validator = new PackageValidator(validationSettings);
    validator.validate(artifact);
  }

  private @NotNull MonitoredArtifact toMonitoredArtifact(TestResult testResult, @NotNull RepoPath repoPath) {
    Ignores ignores = Ignores.read(new RepositoryArtifactProperties(repoPath, repositories));
    return new MonitoredArtifact(repoPath.toString(), testResult, ignores);
  }

  protected Optional<PackageScanner> getScannerForPackageType(RepoPath repoPath) {
    String path = Optional.ofNullable(repoPath.getPath())
      .orElseThrow(() -> new CannotScanException("Path not provided."));
    return getScannerForPackageType(path);
  }

  protected Optional<PackageScanner> getScannerForPackageType(String path) {
    return Ecosystem.fromPackagePath(path).map(this::getScanner);
  }

  private PackageScanner getScanner(Ecosystem ecosystem) {
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

  private boolean shouldTestContinuously() {
    return configurationModule.getPropertyOrDefault(PluginConfiguration.TEST_CONTINUOUSLY).equals("true");
  }

  private Duration durationHoursProperty(PluginConfiguration property, ConfigurationModule configurationModule) {
    return Duration.ofHours(Integer.parseInt(configurationModule.getPropertyOrDefault(property)));
  }
}
