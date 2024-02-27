package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.api.SnykClient;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;

import javax.annotation.Nonnull;

interface AbstractScannerFactory {

  PackageScanner createScanner(@Nonnull ConfigurationModule configurationModule, @Nonnull Repositories repositories, @Nonnull RepoPath repoPath, String pluginVersion);
  SnykClient createSnykClient(@Nonnull ConfigurationModule configurationModule, String pluginVersion, Class client);
}
