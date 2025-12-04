package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.configuration.properties.RepositoryArtifactProperties;
import io.snyk.plugins.artifactory.ecosystem.EcosystemResolver;
import io.snyk.plugins.artifactory.ecosystem.RepositoryMetadataEcosystemResolver;
import io.snyk.plugins.artifactory.model.Ignores;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.model.ValidationSettings;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.fs.ItemInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public class ScannerModule {
  private static final Logger LOG = LoggerFactory.getLogger(ScannerModule.class);
  private final ConfigurationModule configurationModule;
  private final Repositories repositories;
  private final EcosystemResolver ecosystemResolver;
  private final ScannerResolver scannerResolver;
  private final ArtifactResolver artifactResolver;

  public ScannerModule(ConfigurationModule configurationModule, @Nonnull Repositories repositories, ScannerResolver scannerResolver) {
    this.configurationModule = requireNonNull(configurationModule);
    this.repositories = requireNonNull(repositories);

    ecosystemResolver = new RepositoryMetadataEcosystemResolver(repositories);

    this.scannerResolver = scannerResolver;

    artifactResolver = shouldTestContinuously() ? new ArtifactCache(
      durationHoursProperty(PluginConfiguration.TEST_FREQUENCY_HOURS, configurationModule),
      durationHoursProperty(PluginConfiguration.EXTEND_TEST_DEADLINE_HOURS, configurationModule)
    ) : new ReadOnlyArtifactResolver();
  }

  public Optional<MonitoredArtifact> testArtifact(@Nonnull RepoPath repoPath) {
    if(skip(repoPath)) {
      LOG.debug("No ecosystem matching for {}, skipping.", repoPath);
      return Optional.empty();
    }
    return runTest(repoPath).map(artifact -> artifact.write(properties(repoPath)));
  }

  public void filterAccess(@Nonnull RepoPath repoPath) {
    if(skip(repoPath)) {
      LOG.debug("No ecosystem matching for {}, skipping.", repoPath);
      return;
    }

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
    return ecosystemResolver.getFor(repoPath)
      .flatMap(scannerResolver::getFor)
      .map(scanner -> runTestWith(scanner, repoPath));
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
    Instant lastModifiedDate = getLastModifiedDate(repoPath);
    
    // Only apply lastModifiedDate to packages from remote repositories.
    if(lastModifiedDateRemoteOnly() && !isRemoteRepository(repoPath)) {
      lastModifiedDate = null;
    }
    return new MonitoredArtifact(repoPath.toString(), testResult, ignores, lastModifiedDate);
  }

  private Instant getLastModifiedDate(RepoPath repoPath) {
    try {
      ItemInfo itemInfo = repositories.getItemInfo(repoPath);
      if (itemInfo != null) {
        Instant lastModified = Instant.ofEpochMilli(itemInfo.getLastModified());
        return lastModified;
      }
    } catch (Exception e) {
      LOG.debug("Could not retrieve last modified date for {}: {}", repoPath, e);
    }
    return null;
  }

  private boolean isRemoteRepository(RepoPath repoPath) {
    String repoKey = repoPath.getRepoKey();
    RepositoryConfiguration repoConfig = repositories.getRepositoryConfiguration(repoKey);
    String repoType = repoConfig.getType();

    LOG.debug("Found repository type: {}", repoType);

    return repoType == "remote";
  }

  private boolean shouldTestContinuously() {
    return configurationModule.getPropertyOrDefault(PluginConfiguration.TEST_CONTINUOUSLY).equals("true");
  }

  private boolean lastModifiedDateRemoteOnly() {
    return configurationModule.getPropertyOrDefault(PluginConfiguration.SCANNER_LAST_MODIFIED_CHECK_ONLY_REMOTE).equals("true");
  }

  private Duration durationHoursProperty(PluginConfiguration property, ConfigurationModule configurationModule) {
    return Duration.ofHours(Integer.parseInt(configurationModule.getPropertyOrDefault(property)));
  }

  private boolean skip(RepoPath repoPath) {
    return ecosystemResolver.getFor(repoPath).isEmpty();
  }
}
