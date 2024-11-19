package io.snyk.plugins.artifactory.ecosystem;

import org.artifactory.repo.RepoPath;

import java.util.Optional;

public interface EcosystemResolver {

  Optional<Ecosystem> getFor(RepoPath repoPath);
}
