package io.snyk.plugins.artifactory.ecosystem;

import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class RepositoryMetadataEcosystemResolver implements EcosystemResolver {

  private static final Logger LOG = LoggerFactory.getLogger(RepositoryMetadataEcosystemResolver.class);

  private final Repositories repositories;

  public RepositoryMetadataEcosystemResolver(Repositories repositories) {
    this.repositories = repositories;
  }

  @Override
  public Optional<Ecosystem> getFor(RepoPath repoPath) {
    RepositoryConfiguration repositoryConfiguration = repositories.getRepositoryConfiguration(repoPath.getRepoKey());
    if(repositoryConfiguration == null) {
      LOG.error("No repository configuration for {}", repoPath);
      return Optional.empty();
    }

    String packageType = repositoryConfiguration.getPackageType();
    if(packageType == null) {
      LOG.error("No package type for {}", repoPath);
      return Optional.empty();
    }

    return Ecosystem.match(packageType, repoPath.getPath());
  }
}
