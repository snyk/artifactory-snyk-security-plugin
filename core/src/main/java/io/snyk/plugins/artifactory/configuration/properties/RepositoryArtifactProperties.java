package io.snyk.plugins.artifactory.configuration.properties;

import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;

import java.util.Optional;

public class RepositoryArtifactProperties implements ArtifactProperties {

  private final RepoPath repoPath;
  private final Repositories repositories;

  public RepositoryArtifactProperties(RepoPath repoPath, Repositories repositories) {

    this.repoPath = repoPath;
    this.repositories = repositories;
  }

  @Override
  public Optional<String> getProperty(ArtifactProperty key) {
    return Optional.ofNullable(repositories.getProperty(repoPath, key.propertyKey()));
  }

  @Override
  public void setProperty(ArtifactProperty property, String value) {
    repositories.setProperty(repoPath, property.propertyKey(), value);
  }

  @Override
  public boolean hasProperty(ArtifactProperty property) {
    return repositories.hasProperty(repoPath, property.propertyKey());
  }
}
